package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func getFdForAddr(pid int, addr net.IP) int {
	addr_string := ""
	for _, octet := range addr {
		addr_string = fmt.Sprintf("%02X%s", octet, addr_string)
	}
	//fmt.Printf("looking for addr %s\n", addr_string)
	procNetTcp := "/proc/net/tcp"
	procFdDir := fmt.Sprintf("/proc/%d/fd", pid)

	tcpConnections, err := parseProcNetTcp(procNetTcp)
	if err != nil {
		log.Fatal(err)
	}

	fdToInodeMap, err := parseProcFdDir(procFdDir)
	if err != nil {
		log.Fatal(err)
	}

	for fd, inode := range fdToInodeMap {
		if _, found := tcpConnections[inode]; found {
			//fmt.Printf("File Descriptor: %s for %s:%s\n", fd, inode, tcpConnections[inode])
			if strings.Contains(tcpConnections[inode], addr_string) {
				fdint, err := strconv.Atoi(fd)
				if err != nil {
					fdint = 0
				}
				return fdint
			}
		}
	}

	return 0
}

func getFdFromName(name string, addr net.IP, exclude string) (int, int) {
	pids, err := getPIDsByCommandLine(name, exclude)
	if err != nil {
		return 0, 0
	}
	for _, pid := range pids {
		//fmt.Printf("found process %d\n", pid)
		fd := getFdForAddr(pid, addr)
		if fd != 0 {
			return pid, fd
		}
	}
	return 0, 0
}

func getPIDsByCommandLine(targetString string, exclude string) ([]int, error) {
	var pids []int
	procPath := "/proc"

	entries, err := ioutil.ReadDir(procPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}

		cmdlinePath := filepath.Join(procPath, entry.Name(), "cmdline")
		cmdline, err := ioutil.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}

		if strings.Contains(string(cmdline), targetString) && !strings.Contains(string(cmdline), exclude) {
			pid, err := strconv.Atoi(entry.Name())
			if err == nil {
				pids = append(pids, pid)
			}
		}
	}

	return pids, nil
}

func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseProcNetTcp(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	tcpConnections := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		remoteAddress := fields[2]
		inode := fields[9]
		tcpConnections[inode] = remoteAddress
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return tcpConnections, nil
}

func parseProcFdDir(dirPath string) (map[string]string, error) {
	fdToInodeMap := make(map[string]string)
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		fdPath := filepath.Join(dirPath, file.Name())
		link, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") {
			inode := link[8 : len(link)-1]
			fdToInodeMap[file.Name()] = inode
		}
	}
	return fdToInodeMap, nil
}
