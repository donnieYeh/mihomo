# Mihomo Windows 进程网络请求捕获原理

## 概述

Mihomo 是一个基于 Go 语言开发的代理软件，它能够捕获和路由网络流量。在 Windows 系统上，Mihomo 具有强大的进程级别网络请求捕获能力，可以识别每个网络连接对应的进程，并基于进程信息进行流量路由。

## 核心原理

### 1. 系统架构

Mihomo 的 Windows 进程捕获机制主要包含以下组件：

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   应用程序      │───▶│   TUN 虚拟接口   │───▶│   Mihomo 代理   │
│  (Chrome等)     │    │   流量捕获       │    │   进程识别      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │                         │
                              ▼                         ▼
                       ┌──────────────┐         ┌──────────────┐
                       │ Windows      │         │ 规则匹配     │
                       │ 路由表修改   │         │ 流量路由     │
                       └──────────────┘         └──────────────┘
```

### 2. Windows 网络表查询机制

#### 核心 Windows API

Mihomo 使用以下 Windows API 来查询网络连接和进程关联：

```go
// component/process/process_windows.go
const (
    tcpTableFunc      = "GetExtendedTcpTable"     // 获取扩展TCP连接表
    tcpTablePidConn   = 4                         // 包含进程ID的TCP表类型
    udpTableFunc      = "GetExtendedUdpTable"     // 获取扩展UDP连接表  
    udpTablePid       = 1                         // 包含进程ID的UDP表类型
    queryProcNameFunc = "QueryFullProcessImageNameW" // 查询进程完整路径
)
```

#### API 初始化过程

```go
func initWin32API() error {
    // 加载 iphlpapi.dll 动态链接库
    h, err := windows.LoadLibrary("iphlpapi.dll")
    if err != nil {
        return fmt.Errorf("LoadLibrary iphlpapi.dll failed: %s", err.Error())
    }

    // 获取 GetExtendedTcpTable 函数地址
    getExTCPTable, err = windows.GetProcAddress(h, tcpTableFunc)
    
    // 获取 GetExtendedUdpTable 函数地址  
    getExUDPTable, err = windows.GetProcAddress(h, udpTableFunc)

    // 加载 kernel32.dll 获取进程查询函数
    h, err = windows.LoadLibrary("kernel32.dll")
    queryProcName, err = windows.GetProcAddress(h, queryProcNameFunc)
    
    return nil
}
```

### 3. 进程查找算法

#### 网络连接搜索

当捕获到网络连接时，Mihomo 执行以下步骤来识别对应的进程：

```go
func findProcessName(network string, ip netip.Addr, srcPort int) (uint32, string, error) {
    // 1. 确定地址族 (IPv4/IPv6)
    family := windows.AF_INET
    if ip.Is6() {
        family = windows.AF_INET6
    }

    // 2. 根据协议类型选择对应的API函数
    var class int
    var fn uintptr
    switch network {
    case TCP:
        fn = getExTCPTable      // TCP连接表
        class = tcpTablePidConn
    case UDP:
        fn = getExUDPTable      // UDP连接表
        class = udpTablePid
    }

    // 3. 获取系统网络连接表
    buf, err := getTransportTable(fn, family, class)
    
    // 4. 在连接表中搜索匹配的连接
    s := newSearcher(family == windows.AF_INET, network == TCP)
    pid, err := s.Search(buf, ip, uint16(srcPort))
    
    // 5. 根据PID获取进程路径
    processPath, err := getExecPathFromPID(pid)
    return 0, processPath, err
}
```

#### 连接表搜索逻辑

```go
func (s *searcher) Search(b []byte, ip netip.Addr, port uint16) (uint32, error) {
    n := int(readNativeUint32(b[:4]))  // 读取连接数量
    itemSize := s.itemSize              // 每个连接记录的大小
    
    for i := 0; i < n; i++ {
        row := b[4+itemSize*i : 4+itemSize*(i+1)]  // 获取单个连接记录
        
        // 对于TCP连接，只检查已建立的连接 (状态 = 5)
        if s.tcpState >= 0 {
            tcpState := readNativeUint32(row[s.tcpState : s.tcpState+4])
            if tcpState != 5 {  // MIB_TCP_STATE_ESTAB
                continue
            }
        }
        
        // 比较端口号 (需要进行字节序转换)
        srcPort := syscall.Ntohs(uint16(readNativeUint32(row[s.port : s.port+4])))
        if srcPort != port {
            continue
        }
        
        // 比较IP地址
        srcIP, _ := netip.AddrFromSlice(row[s.ip : s.ip+s.ipSize])
        srcIP = srcIP.Unmap()
        if ip != srcIP && (!srcIP.IsUnspecified() || s.tcpState != -1) {
            continue
        }
        
        // 找到匹配的连接，返回进程ID
        pid := readNativeUint32(row[s.pid : s.pid+4])
        return pid, nil
    }
    return 0, ErrNotFound
}
```

### 4. 进程路径获取

```go
func getExecPathFromPID(pid uint32) (string, error) {
    // 处理特殊的系统进程
    switch pid {
    case 0:
        return ":System Idle Process", nil  // 系统空闲进程
    case 4:
        return ":System", nil               // Windows内核进程
    }
    
    // 打开进程句柄
    h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
    if err != nil {
        return "", err
    }
    defer windows.CloseHandle(h)
    
    // 查询进程完整路径
    buf := make([]uint16, syscall.MAX_LONG_PATH)
    size := uint32(len(buf))
    r1, _, err := syscall.Syscall6(
        queryProcName, 4,
        uintptr(h),                                    // 进程句柄
        uintptr(0),                                    // 查询标志
        uintptr(unsafe.Pointer(&buf[0])),             // 输出缓冲区
        uintptr(unsafe.Pointer(&size)),               // 缓冲区大小
        0, 0)
    
    if r1 == 0 {
        return "", err
    }
    return syscall.UTF16ToString(buf[:size]), nil
}
```

## 流量捕获机制

### 1. TUN 接口模式

TUN 接口是 Mihomo 在 Windows 上捕获进程网络请求的主要方式：

#### TUN 接口创建

```go
// listener/sing_tun/server_windows.go
func tunNew(options tun.Options) (tunIf tun.Tun, err error) {
    maxRetry := 3
    for i := 0; i < maxRetry; i++ {
        timeBegin := time.Now()
        tunIf, err = tun.New(options)    // 创建TUN接口
        if err == nil {
            return
        }
        // 处理 "文件已存在" 错误的重试逻辑
        timeEnd := time.Now()
        if timeEnd.Sub(timeBegin) < 1*time.Second {
            return
        }
        log.Warnln("Start Tun interface timeout: %s [retrying %d/%d]", err, i+1, maxRetry)
    }
    return
}
```

#### 路由表操作

TUN 接口通过修改 Windows 路由表来捕获流量：

1. **创建虚拟网络接口** - 通常命名为 "Meta" 或 "tun0"
2. **添加路由规则** - 将目标流量路由到 TUN 接口
3. **流量拦截** - 所有经过 TUN 接口的数据包都会被 Mihomo 处理

### 2. 其他捕获方式

#### 代理模式
- **HTTP/HTTPS 代理** - 应用程序主动配置代理
- **SOCKS 代理** - 支持 SOCKS4/SOCKS5 协议

#### 透明代理 (Linux)
- **REDIRECT** - iptables REDIRECT 目标  
- **TPROXY** - iptables TPROXY 目标

## 集成流程

### 1. 连接处理流程

```go
// tunnel/tunnel.go
func (t tunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
    connCtx := icontext.NewConnContext(conn, metadata)
    handleTCPConn(connCtx)
}
```

### 2. 进程信息查找

```go
helper := C.RuleMatchHelper{
    FindProcess: func() {
        if attemptProcessLookup {
            attemptProcessLookup = false
            if !features.CMFA {
                // 普通进程查找
                uid, path, err := P.FindProcessName(
                    metadata.NetWork.String(), 
                    metadata.SrcIP, 
                    int(metadata.SrcPort))
                if err != nil {
                    log.Debugln("[Process] find process error for %s: %v", 
                        metadata.String(), err)
                } else {
                    metadata.Process = filepath.Base(path)      // 进程名称
                    metadata.ProcessPath = path                 // 完整路径
                    metadata.Uid = uid                          // 用户ID
                }
            }
        }
    },
}
```

### 3. 规则匹配和路由

进程信息获取后，可以基于以下规则进行匹配：

```yaml
rules:
  - PROCESS-NAME,chrome.exe,Proxy1          # 进程名匹配
  - PROCESS-PATH,C:\Program Files\App\app.exe,DIRECT  # 完整路径匹配
  - PROCESS-NAME-REGEX,.*browser.*,Proxy2   # 正则表达式匹配
```

## 数据结构

### 连接元数据

```go
// constant/metadata.go
type Metadata struct {
    NetWork      NetWork    `json:"network"`        // TCP/UDP
    Type         Type       `json:"type"`           // 连接类型 (TUN/Proxy等)
    SrcIP        netip.Addr `json:"sourceIP"`       // 源IP地址  
    DstIP        netip.Addr `json:"destinationIP"`  // 目标IP地址
    SrcPort      uint16     `json:"sourcePort"`     // 源端口
    DstPort      uint16     `json:"destinationPort"` // 目标端口
    Uid          uint32     `json:"uid"`            // 用户ID
    Process      string     `json:"process"`        // 进程名称
    ProcessPath  string     `json:"processPath"`    // 进程完整路径
    // ... 其他字段
}
```

### Windows 网络表结构

Windows 网络连接表的内存布局：

#### IPv4 TCP 连接 (MIB_TCPROW_OWNER_PID)
```
偏移  大小  字段
0     4     dwState      (连接状态)
4     4     dwLocalAddr  (本地IP地址)  
8     4     dwLocalPort  (本地端口)
12    4     dwRemoteAddr (远程IP地址)
16    4     dwRemotePort (远程端口)
20    4     dwOwningPid  (进程ID)
```

#### IPv4 UDP 连接 (MIB_UDPROW_OWNER_PID)  
```
偏移  大小  字段
0     4     dwLocalAddr  (本地IP地址)
4     4     dwLocalPort  (本地端口)  
8     4     dwOwningPid  (进程ID)
```

## 性能优化

### 1. 按需查找

进程查找是一个相对昂贵的操作，Mihomo 采用按需查找的策略：

```go
switch FindProcessMode() {
case P.FindProcessAlways:
    helper.FindProcess()        // 总是查找进程
    helper.FindProcess = nil
case P.FindProcessOff:
    helper.FindProcess = nil    // 关闭进程查找
case P.FindProcessStrict:
    // 仅在规则需要时查找 (默认模式)
}
```

### 2. 缓存机制

虽然代码中没有显式的缓存，但 Windows 系统的网络表查询本身具有一定的缓存效果。

## 系统要求和限制

### 权限要求
- **管理员权限** - 访问扩展网络表需要管理员权限
- **驱动程序** - TUN 接口可能需要特定的网络驱动

### 兼容性
- **Windows 版本** - 支持 Windows 7 及以上版本
- **架构支持** - 支持 x86 和 x64 架构

### 已知限制
1. **UDP 连接** - UDP 连接的进程映射可能不如 TCP 准确
2. **内核进程** - 某些系统内核进程 (PID 0, 4) 需要特殊处理
3. **性能开销** - 进程查找会增加一定的延迟

## 实际应用示例

### 配置示例

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
  # 基于进程的路由规则
  - PROCESS-NAME,QQ.exe,Proxy-Gaming
  - PROCESS-NAME,WeChat.exe,DIRECT  
  - PROCESS-NAME,chrome.exe,Proxy-Web
  - PROCESS-PATH,C:\Program Files\Steam\steam.exe,Proxy-Gaming
  - PROCESS-NAME-REGEX,.*browser.*,Proxy-Web
```

### 日志输出示例

```
[Process] find process for 192.168.1.100:54231 -> chrome.exe (C:\Program Files\Google\Chrome\Application\chrome.exe)
[Rule] 192.168.1.100:54231(chrome.exe) match PROCESS-NAME(chrome.exe) using Proxy-Web
```

## 总结

Mihomo 在 Windows 上的进程网络请求捕获机制是一个复杂而精密的系统，它结合了：

1. **Windows 系统 API** - 利用 `GetExtendedTcpTable`、`GetExtendedUdpTable` 等 API 获取网络连接信息
2. **TUN 虚拟接口** - 通过创建虚拟网络接口和路由表操作来捕获流量  
3. **进程查找算法** - 通过匹配 IP、端口信息来识别对应的进程
4. **规则引擎** - 基于进程信息进行灵活的流量路由

这种设计使得 Mihomo 能够在应用层面实现精细化的网络流量控制，无需修改各个应用程序的网络配置，就能实现基于进程的智能代理和路由。