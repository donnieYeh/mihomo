// Example: Simplified Windows Process Network Capture Demo
// This example demonstrates the core concepts used by Mihomo for process identification

package main

import (
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API constants
const (
	tcpTableFunc    = "GetExtendedTcpTable"
	tcpTablePidConn = 4
)

var getExTCPTable uintptr

// Initialize Windows API functions
func initAPI() error {
	h, err := windows.LoadLibrary("iphlpapi.dll")
	if err != nil {
		return err
	}

	getExTCPTable, err = windows.GetProcAddress(h, tcpTableFunc)
	if err != nil {
		return err
	}

	return nil
}

// TCPRowOwnerPID represents a TCP connection with process ID
type TCPRowOwnerPID struct {
	State      uint32 // Connection state
	LocalAddr  uint32 // Local IP address
	LocalPort  uint32 // Local port
	RemoteAddr uint32 // Remote IP address  
	RemotePort uint32 // Remote port
	OwningPid  uint32 // Process ID
}

// Get TCP connection table with process IDs
func getTCPTable() ([]TCPRowOwnerPID, error) {
	// Get required buffer size
	var size uint32
	_, _, _ = syscall.Syscall6(getExTCPTable, 6,
		0,                                    // NULL pointer
		uintptr(unsafe.Pointer(&size)),       // Size pointer
		0,                                    // Order
		uintptr(windows.AF_INET),            // Address family
		uintptr(tcpTablePidConn),            // Table class
		0)

	// Allocate buffer
	buf := make([]byte, size)
	ptr := uintptr(unsafe.Pointer(&buf[0]))

	// Get actual table
	ret, _, _ := syscall.Syscall6(getExTCPTable, 6,
		ptr,                                  // Buffer pointer
		uintptr(unsafe.Pointer(&size)),       // Size pointer
		0,                                    // Order
		uintptr(windows.AF_INET),            // Address family
		uintptr(tcpTablePidConn),            // Table class
		0)

	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed with error %d", ret)
	}

	// Parse the table
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	entries := make([]TCPRowOwnerPID, numEntries)

	// Each entry is 24 bytes (6 * 4 bytes)
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*24 // Skip the count (4 bytes) + i * sizeof(TCPRowOwnerPID)
		entry := (*TCPRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		entries[i] = *entry
	}

	return entries, nil
}

// Find process ID for a given connection
func findProcessByConnection(localIP netip.Addr, localPort uint16) (uint32, error) {
	if err := initAPI(); err != nil {
		return 0, err
	}

	entries, err := getTCPTable()
	if err != nil {
		return 0, err
	}

	// Convert IP to uint32 (little-endian)
	ipBytes := localIP.As4()
	targetIP := uint32(ipBytes[0]) | uint32(ipBytes[1])<<8 | 
	           uint32(ipBytes[2])<<16 | uint32(ipBytes[3])<<24

	// Convert port to network byte order
	targetPort := uint32(syscall.Htons(localPort))

	for _, entry := range entries {
		// Check if connection is established (state 5)
		if entry.State == 5 && 
		   entry.LocalAddr == targetIP && 
		   entry.LocalPort == targetPort {
			return entry.OwningPid, nil
		}
	}

	return 0, fmt.Errorf("process not found for %s:%d", localIP, localPort)
}

// Get process name from PID
func getProcessName(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, 260) // MAX_PATH
	size := uint32(len(buf))

	kernel32 := windows.NewLazyDLL("kernel32.dll")
	queryFullProcessImageName := kernel32.NewProc("QueryFullProcessImageNameW")

	ret, _, err := queryFullProcessImageName.Call(
		uintptr(h),
		0, // flags
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)))

	if ret == 0 {
		return "", err
	}

	return syscall.UTF16ToString(buf[:size]), nil
}

// Example usage
func main() {
	// Example: Find process for local connection 127.0.0.1:8080
	ip := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	port := uint16(8080)

	fmt.Printf("Looking for process with connection %s:%d\n", ip, port)

	pid, err := findProcessByConnection(ip, port)
	if err != nil {
		fmt.Printf("Error finding process: %v\n", err)
		return
	}

	fmt.Printf("Found process ID: %d\n", pid)

	processName, err := getProcessName(pid)
	if err != nil {
		fmt.Printf("Error getting process name: %v\n", err)
		return
	}

	fmt.Printf("Process: %s\n", processName)
}

/* Expected output (example):
Looking for process with connection 127.0.0.1:8080
Found process ID: 1234
Process: C:\Program Files\Google\Chrome\Application\chrome.exe
*/