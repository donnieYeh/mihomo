# Mihomo Windows Process Network Request Capture Principles

## Overview

Mihomo is a Go-based proxy software that can capture and route network traffic. On Windows systems, Mihomo has powerful process-level network request capture capabilities, allowing it to identify the process corresponding to each network connection and route traffic based on process information.

## Core Principles

### 1. System Architecture

The Windows process capture mechanism in Mihomo consists of the following components:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Applications  │───▶│   TUN Interface  │───▶│   Mihomo Proxy  │
│  (Chrome, etc.) │    │  Traffic Capture │    │ Process Identification│
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │                         │
                              ▼                         ▼
                       ┌──────────────┐         ┌──────────────┐
                       │ Windows      │         │ Rule Matching│
                       │ Route Table  │         │ Traffic Route│
                       └──────────────┘         └──────────────┘
```

### 2. Windows Network Table Query Mechanism

#### Core Windows APIs

Mihomo uses the following Windows APIs to query network connections and their associated processes:

```go
// component/process/process_windows.go
const (
    tcpTableFunc      = "GetExtendedTcpTable"     // Get extended TCP connection table
    tcpTablePidConn   = 4                         // TCP table type with process ID
    udpTableFunc      = "GetExtendedUdpTable"     // Get extended UDP connection table  
    udpTablePid       = 1                         // UDP table type with process ID
    queryProcNameFunc = "QueryFullProcessImageNameW" // Query full process path
)
```

#### API Initialization Process

```go
func initWin32API() error {
    // Load iphlpapi.dll dynamic link library
    h, err := windows.LoadLibrary("iphlpapi.dll")
    if err != nil {
        return fmt.Errorf("LoadLibrary iphlpapi.dll failed: %s", err.Error())
    }

    // Get GetExtendedTcpTable function address
    getExTCPTable, err = windows.GetProcAddress(h, tcpTableFunc)
    
    // Get GetExtendedUdpTable function address  
    getExUDPTable, err = windows.GetProcAddress(h, udpTableFunc)

    // Load kernel32.dll to get process query function
    h, err = windows.LoadLibrary("kernel32.dll")
    queryProcName, err = windows.GetProcAddress(h, queryProcNameFunc)
    
    return nil
}
```

### 3. Process Finding Algorithm

#### Network Connection Search

When a network connection is captured, Mihomo performs the following steps to identify the corresponding process:

```go
func findProcessName(network string, ip netip.Addr, srcPort int) (uint32, string, error) {
    // 1. Determine address family (IPv4/IPv6)
    family := windows.AF_INET
    if ip.Is6() {
        family = windows.AF_INET6
    }

    // 2. Select corresponding API function based on protocol type
    var class int
    var fn uintptr
    switch network {
    case TCP:
        fn = getExTCPTable      // TCP connection table
        class = tcpTablePidConn
    case UDP:
        fn = getExUDPTable      // UDP connection table
        class = udpTablePid
    }

    // 3. Get system network connection table
    buf, err := getTransportTable(fn, family, class)
    
    // 4. Search for matching connection in the table
    s := newSearcher(family == windows.AF_INET, network == TCP)
    pid, err := s.Search(buf, ip, uint16(srcPort))
    
    // 5. Get process path from PID
    processPath, err := getExecPathFromPID(pid)
    return 0, processPath, err
}
```

#### Connection Table Search Logic

```go
func (s *searcher) Search(b []byte, ip netip.Addr, port uint16) (uint32, error) {
    n := int(readNativeUint32(b[:4]))  // Read number of connections
    itemSize := s.itemSize              // Size of each connection record
    
    for i := 0; i < n; i++ {
        row := b[4+itemSize*i : 4+itemSize*(i+1)]  // Get single connection record
        
        // For TCP connections, only check established connections (state = 5)
        if s.tcpState >= 0 {
            tcpState := readNativeUint32(row[s.tcpState : s.tcpState+4])
            if tcpState != 5 {  // MIB_TCP_STATE_ESTAB
                continue
            }
        }
        
        // Compare port number (requires byte order conversion)
        srcPort := syscall.Ntohs(uint16(readNativeUint32(row[s.port : s.port+4])))
        if srcPort != port {
            continue
        }
        
        // Compare IP address
        srcIP, _ := netip.AddrFromSlice(row[s.ip : s.ip+s.ipSize])
        srcIP = srcIP.Unmap()
        if ip != srcIP && (!srcIP.IsUnspecified() || s.tcpState != -1) {
            continue
        }
        
        // Found matching connection, return process ID
        pid := readNativeUint32(row[s.pid : s.pid+4])
        return pid, nil
    }
    return 0, ErrNotFound
}
```

### 4. Process Path Retrieval

```go
func getExecPathFromPID(pid uint32) (string, error) {
    // Handle special system processes
    switch pid {
    case 0:
        return ":System Idle Process", nil  // System idle process
    case 4:
        return ":System", nil               // Windows kernel process
    }
    
    // Open process handle
    h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
    if err != nil {
        return "", err
    }
    defer windows.CloseHandle(h)
    
    // Query full process path
    buf := make([]uint16, syscall.MAX_LONG_PATH)
    size := uint32(len(buf))
    r1, _, err := syscall.Syscall6(
        queryProcName, 4,
        uintptr(h),                                    // Process handle
        uintptr(0),                                    // Query flags
        uintptr(unsafe.Pointer(&buf[0])),             // Output buffer
        uintptr(unsafe.Pointer(&size)),               // Buffer size
        0, 0)
    
    if r1 == 0 {
        return "", err
    }
    return syscall.UTF16ToString(buf[:size]), nil
}
```

## Traffic Capture Mechanisms

### 1. TUN Interface Mode

The TUN interface is the primary method for capturing process network requests on Windows:

#### TUN Interface Creation

```go
// listener/sing_tun/server_windows.go
func tunNew(options tun.Options) (tunIf tun.Tun, err error) {
    maxRetry := 3
    for i := 0; i < maxRetry; i++ {
        timeBegin := time.Now()
        tunIf, err = tun.New(options)    // Create TUN interface
        if err == nil {
            return
        }
        // Retry logic for "file already exists" error
        timeEnd := time.Now()
        if timeEnd.Sub(timeBegin) < 1*time.Second {
            return
        }
        log.Warnln("Start Tun interface timeout: %s [retrying %d/%d]", err, i+1, maxRetry)
    }
    return
}
```

#### Route Table Operations

The TUN interface captures traffic by modifying the Windows route table:

1. **Create Virtual Network Interface** - Usually named "Meta" or "tun0"
2. **Add Route Rules** - Route target traffic to the TUN interface
3. **Traffic Interception** - All packets passing through the TUN interface are processed by Mihomo

### 2. Other Capture Methods

#### Proxy Mode
- **HTTP/HTTPS Proxy** - Applications actively configure proxy
- **SOCKS Proxy** - Support for SOCKS4/SOCKS5 protocols

#### Transparent Proxy (Linux)
- **REDIRECT** - iptables REDIRECT target  
- **TPROXY** - iptables TPROXY target

## Integration Flow

### 1. Connection Handling Process

```go
// tunnel/tunnel.go
func (t tunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
    connCtx := icontext.NewConnContext(conn, metadata)
    handleTCPConn(connCtx)
}
```

### 2. Process Information Lookup

```go
helper := C.RuleMatchHelper{
    FindProcess: func() {
        if attemptProcessLookup {
            attemptProcessLookup = false
            if !features.CMFA {
                // Normal process lookup
                uid, path, err := P.FindProcessName(
                    metadata.NetWork.String(), 
                    metadata.SrcIP, 
                    int(metadata.SrcPort))
                if err != nil {
                    log.Debugln("[Process] find process error for %s: %v", 
                        metadata.String(), err)
                } else {
                    metadata.Process = filepath.Base(path)      // Process name
                    metadata.ProcessPath = path                 // Full path
                    metadata.Uid = uid                          // User ID
                }
            }
        }
    },
}
```

### 3. Rule Matching and Routing

After process information is obtained, matching can be performed based on the following rules:

```yaml
rules:
  - PROCESS-NAME,chrome.exe,Proxy1          # Process name matching
  - PROCESS-PATH,C:\Program Files\App\app.exe,DIRECT  # Full path matching
  - PROCESS-NAME-REGEX,.*browser.*,Proxy2   # Regular expression matching
```

## Data Structures

### Connection Metadata

```go
// constant/metadata.go
type Metadata struct {
    NetWork      NetWork    `json:"network"`        // TCP/UDP
    Type         Type       `json:"type"`           // Connection type (TUN/Proxy etc.)
    SrcIP        netip.Addr `json:"sourceIP"`       // Source IP address  
    DstIP        netip.Addr `json:"destinationIP"`  // Destination IP address
    SrcPort      uint16     `json:"sourcePort"`     // Source port
    DstPort      uint16     `json:"destinationPort"` // Destination port
    Uid          uint32     `json:"uid"`            // User ID
    Process      string     `json:"process"`        // Process name
    ProcessPath  string     `json:"processPath"`    // Full process path
    // ... other fields
}
```

### Windows Network Table Structure

Memory layout of Windows network connection table:

#### IPv4 TCP Connection (MIB_TCPROW_OWNER_PID)
```
Offset Size Field
0      4    dwState      (Connection state)
4      4    dwLocalAddr  (Local IP address)  
8      4    dwLocalPort  (Local port)
12     4    dwRemoteAddr (Remote IP address)
16     4    dwRemotePort (Remote port)
20     4    dwOwningPid  (Process ID)
```

#### IPv4 UDP Connection (MIB_UDPROW_OWNER_PID)  
```
Offset Size Field
0      4    dwLocalAddr  (Local IP address)
4      4    dwLocalPort  (Local port)  
8      4    dwOwningPid  (Process ID)
```

## Performance Optimization

### 1. On-Demand Lookup

Process lookup is a relatively expensive operation, so Mihomo uses an on-demand lookup strategy:

```go
switch FindProcessMode() {
case P.FindProcessAlways:
    helper.FindProcess()        // Always lookup process
    helper.FindProcess = nil
case P.FindProcessOff:
    helper.FindProcess = nil    // Disable process lookup
case P.FindProcessStrict:
    // Only lookup when rules require it (default mode)
}
```

### 2. Caching Mechanism

While there's no explicit caching in the code, the Windows system's network table query itself has some caching effects.

## System Requirements and Limitations

### Permission Requirements
- **Administrator Privileges** - Accessing extended network tables requires administrator privileges
- **Drivers** - TUN interface may require specific network drivers

### Compatibility
- **Windows Version** - Supports Windows 7 and above
- **Architecture Support** - Supports both x86 and x64 architectures

### Known Limitations
1. **UDP Connections** - UDP connection process mapping may not be as accurate as TCP
2. **Kernel Processes** - Certain system kernel processes (PID 0, 4) require special handling
3. **Performance Overhead** - Process lookup adds some latency

## Practical Application Example

### Configuration Example

```yaml
# config.yaml
tun:
  enable: true
  stack: system
  dns-hijack:
    - 8.8.8.8:53
  auto-route: true
  auto-detect-interface: true

process-mode: always  # always, off, strict

rules:
  # Process-based routing rules
  - PROCESS-NAME,QQ.exe,Proxy-Gaming
  - PROCESS-NAME,WeChat.exe,DIRECT  
  - PROCESS-NAME,chrome.exe,Proxy-Web
  - PROCESS-PATH,C:\Program Files\Steam\steam.exe,Proxy-Gaming
  - PROCESS-NAME-REGEX,.*browser.*,Proxy-Web
```

### Log Output Example

```
[Process] find process for 192.168.1.100:54231 -> chrome.exe (C:\Program Files\Google\Chrome\Application\chrome.exe)
[Rule] 192.168.1.100:54231(chrome.exe) match PROCESS-NAME(chrome.exe) using Proxy-Web
```

## Summary

Mihomo's process network request capture mechanism on Windows is a complex and sophisticated system that combines:

1. **Windows System APIs** - Utilizing APIs like `GetExtendedTcpTable` and `GetExtendedUdpTable` to obtain network connection information
2. **TUN Virtual Interface** - Creating virtual network interfaces and route table operations to capture traffic  
3. **Process Finding Algorithm** - Identifying corresponding processes by matching IP and port information
4. **Rule Engine** - Flexible traffic routing based on process information

This design enables Mihomo to implement fine-grained network traffic control at the application level, allowing intelligent proxy and routing based on processes without needing to modify the network configuration of individual applications.