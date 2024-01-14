/*
Copyright 2023 David Hadas

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/davidhadas/seal-control/pkg/log"
	"github.com/fntlnz/mountinfo"
)

// Ignore standard mounts including
// "proc":  {"/proc", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys"},
// "tmpfs": {"/proc/timer_list", "/dev/shm", "/dev", "/sys/fs/cgroup"},
// "cgroup": {"/sys/fs/cgroup/cpuset", "/sys/fs/cgroup/devices", "/sys/fs/cgroup/cpu,cpuacct",
//
//	"/sys/fs/cgroup/perf_event", "/sys/fs/cgroup/blkio", "/sys/fs/cgroup/memory"},
//
// "devpts":  {"/dev/pts"},
// "mqueue":  {"/dev/mqueue"},
// "sysfs":   {"/sys"},
// "overlay": {"/"},
func check_mounts(devEnvFlag bool, mounts []string, config map[string]string) error {
	var err error
	logger := log.Log

	mountExempt := config["MountExempt"]
	exemptions := strings.Split(mountExempt, ",")
	var minfo []mountinfo.Mountinfo
	if devEnvFlag {
		minfo, err = mountinfo.GetMountInfo("/tmp/mountinfo")
	} else {
		minfo, err = mountinfo.GetMountInfo("/proc/self/mountinfo")
	}
	if err != nil {
		logger.Infof("error getting mountinfo: %v", err)
	}

	for _, m := range minfo {
		if slices.Contains(mounts, m.MountPoint) {
			continue
		}
		if slices.Contains(exemptions, m.MountPoint) {
			continue
		}
		switch m.FilesystemType {
		case "tmpfs":
			if strings.HasPrefix(m.MountPoint, "/proc/") ||
				strings.HasPrefix(m.MountPoint, "/dev") ||
				strings.HasPrefix(m.MountPoint, "/mnt") ||
				strings.HasPrefix(m.MountPoint, "/run") ||
				strings.HasPrefix(m.MountPoint, "/sys/") {
				continue
			}
		case "proc":
			if strings.HasPrefix(m.MountPoint, "/proc") {
				continue
			}
		case "cgroup", "cgroup2":
			if strings.HasPrefix(m.MountPoint, "/sys/fs/cgroup/") {
				continue
			}
		case "devpts":
			if m.MountPoint == "/dev/pts" {
				continue
			}
		case "mqueue":
			if m.MountPoint == "/dev/mqueue" {
				continue
			}
		case "sysfs":
			if m.MountPoint == "/sys" {
				continue
			}
		case "overlay":
			if m.MountPoint == "/" {
				continue
			}
		case "virtiofs":
			if m.MountPoint == "/etc/hosts" || // DoS attacks
				m.MountPoint == "/etc/hostname" ||
				m.MountPoint == "/etc/resolv.conf" ||
				m.MountPoint == "/dev/termination-log" ||
				strings.HasPrefix(m.MountPoint, "/run/seal/") ||
				strings.HasPrefix(m.MountPoint, "/run/secrets/") ||
				strings.HasPrefix(m.MountPoint, "/mnt/") {
				continue
			}
		}

		for _, val := range mounts {
			fmt.Printf("'%s' vs '%s' ==> %t\n", m.MountPoint, val, m.MountPoint == val)
		}
		return fmt.Errorf("ilegal mount to %s: '%s'", m.FilesystemType, m.MountPoint)
	}
	return nil
}

func testHostname(devEnvFlag bool) error {
	var err error
	var fp *os.File
	if devEnvFlag {
		fp, err = os.Open("/tmp/hostname")
	} else {
		fp, err = os.Open("/etc/hostname")
	}
	if err != nil {
		return fmt.Errorf("failed to open: %w", err)
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	scanner.Buffer(make([]byte, 0, 64), 64)
	scanner.Scan()
	hostname := scanner.Bytes()
	if err := checkName(hostname); err != nil {
		return fmt.Errorf("hostname '%s': %w", hostname, err)
	}
	return nil
}

func testHosts(devEnvFlag bool) error {
	var err error
	var fp *os.File
	if devEnvFlag {
		fp, err = os.Open("/tmp/hosts")
	} else {
		fp, err = os.Open("/etc/hosts")
	}
	if err != nil {
		return fmt.Errorf("failed to open: %w", err)
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	scanner.Buffer(make([]byte, 1024), 1024)

	space := regexp.MustCompile(`\s+`)

	i := 0
	for scanner.Scan() {
		i += 1
		if i > 256 {
			return fmt.Errorf("too many lines")
		}
		hostline := scanner.Bytes()
		if len(hostline) > 256 {
			return fmt.Errorf("line too long: '%s'", hostline)
		}

		// trim comment
		if comment := bytes.IndexByte(hostline, 35); comment >= 0 {
			hostline = hostline[:comment]
		}

		// trim ending
		hostline = bytes.TrimRight(hostline, "\r\t ")

		//replace tabs and whitespaces with a single whitespace
		hostline = space.ReplaceAll(hostline, []byte{32})

		if len(hostline) < 2 { // empty lines
			continue
		}

		if hostline[0] == 32 { // start with a whitespace
			return fmt.Errorf("ilegal line: '%s'", hostline)
		}
		hostsplits := bytes.Split(hostline, []byte{32}) // split by space
		if len(hostsplits) < 2 {
			return fmt.Errorf("ilegal line structure: '%s'", hostline)
		}
		ip := hostsplits[0]
		parsedIp, err := netip.ParseAddr(string(ip))
		if err != nil {
			return fmt.Errorf("host line '%s': %w", hostline, err)
		}

		for _, name := range hostsplits[1:] {
			if err := checkDomainName(name); err != nil {
				return fmt.Errorf("name '%s': %w", name, err)
			}
			if bytes.Equal(name, []byte("localhost")) && !parsedIp.IsLoopback() {
				return fmt.Errorf("localhost with non loopback ip %v", parsedIp)
			}
			if bytes.Equal(name, []byte("ip6-localhost")) && !parsedIp.IsLoopback() {
				return fmt.Errorf("ip6-localhost with non loopback ip %v", parsedIp)
			}
			if bytes.Equal(name, []byte("ip6-loopback")) && !parsedIp.IsLoopback() {
				return fmt.Errorf("ip6-loopback with non loopback ip %v", parsedIp)
			}
		}
	}
	return nil
}

func checkName(name []byte) error {
	if len(name) > 63 {
		return fmt.Errorf("name too long: '%s'", name)
	}
	isLegalHostnameChar := regexp.MustCompile(`^[a-z]([a-z0-9-]*[a-z0-9])?$`).MatchString
	if !isLegalHostnameChar(string(name)) {
		return fmt.Errorf("not a valid name: '%s'", name)
	}

	return nil
}

func checkDomainName(name []byte) error {
	if len(name) > 255 {
		return fmt.Errorf("domain name too long: '%s'", name)
	}
	namesplits := bytes.Split(name, []byte{46}) // split by period
	for _, subname := range namesplits {
		if err := checkName(subname); err != nil {
			return fmt.Errorf("not a valid name: '%s'", name)
		}
	}
	return nil
}

func testResolv(devEnvFlag bool) error {
	var err error
	var fp *os.File
	if devEnvFlag {
		fp, err = os.Open("/tmp/resolv.conf")
	} else {
		fp, err = os.Open("/etc/resolv.conf")
	}
	if err != nil {
		return fmt.Errorf("failed to open: %w", err)
	}

	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	scanner.Buffer(make([]byte, 260), 260)

	space := regexp.MustCompile(`\s+`)

	i := 0
	for scanner.Scan() {
		i += 1
		if i > 256 {
			return fmt.Errorf("too many lines")
		}
		resolvline := scanner.Bytes()
		if len(resolvline) > 259 {
			return fmt.Errorf("line too long: '%s'", resolvline)
		}

		// skip comment
		if resolvline[0] == 35 || resolvline[0] == 59 {
			continue
		}

		// trim ending
		resolvline = bytes.TrimRight(resolvline, "\r\t ")

		//replace tabs and whitespaces with a single whitespace
		resolvline = space.ReplaceAll(resolvline, []byte{32})

		if len(resolvline) < 2 { // empty lines
			continue
		}

		if resolvline[0] == 32 { // start with a whitespace
			return fmt.Errorf("ilegal line: '%s'", resolvline)
		}
		resolvsplits := bytes.Split(resolvline, []byte{32}) // split by space
		if len(resolvsplits) < 2 {
			return fmt.Errorf("ilegal line structure: '%s'", resolvline)
		}
		config := resolvsplits[0]
		switch string(config) {
		case "nameserver":
			if len(resolvsplits) != 2 {
				return fmt.Errorf("nameserver '%s': ilegal parts in line", resolvline)
			}
			ip := resolvsplits[1]

			if _, err := netip.ParseAddr(string(ip)); err != nil {
				return fmt.Errorf("nameserver '%s': %w", ip, err)
			}
		case "domain":
			if len(resolvsplits) != 2 {
				return fmt.Errorf("domain '%s': ilegal parts in line", resolvline)
			}
			if err := checkDomainName(resolvsplits[1]); err != nil {
				return fmt.Errorf("domain '%s': %w", resolvline, err)
			}
		case "search":
			if len(resolvsplits) > 7 {
				return fmt.Errorf("search '%s': too many parts", resolvline)
			}
			for _, name := range resolvsplits[1:] {
				if err := checkDomainName(name); err != nil {
					return fmt.Errorf("search '%s': %w", resolvline, err)
				}
			}
		case "sortlist":
			if len(resolvsplits) > 11 {
				return fmt.Errorf("sortlist '%s': too many parts", resolvline)
			}
			for _, ipmask := range resolvsplits[1:] {
				parts := bytes.Split(ipmask, []byte{57}) // "/"
				switch len(parts) {
				case 1:
					if _, err := netip.ParseAddr(string(parts[0])); err != nil {
						return fmt.Errorf("sortlist ip '%s': %w", resolvline, err)
					}
				case 2:
					if ip, err := netip.ParseAddr(string(parts[0])); err != nil && ip.IsValid() {
						return fmt.Errorf("sortlist ip '%s': %w", resolvline, err)
					}
					if mask, err := netip.ParseAddr(string(parts[1])); err != nil && mask.IsValid() {
						return fmt.Errorf("sortlist '%s': %w", resolvline, err)
					}
				default:
					return fmt.Errorf("sortlist '%s': ilegal ip/mask", resolvline)
				}
			}
		case "options":
			if len(resolvsplits) > 2 {
				return fmt.Errorf("options '%s': too many parts", resolvline)
			}
			op := string(resolvsplits[1])
			if op == "debug" || op == "rotate" || op == "no-check-names" ||
				op == "inet6" || op == "ip6-bytestring" || op == "ip6-dotint/no-ip6-dotint" ||
				op == "edns0" || op == "single-request" || op == "single-request-reopen" {
				continue
			}
			if strings.HasPrefix(op, "ndots:") {
				if _, err := strconv.Atoi(op[6:]); err != nil {
					return fmt.Errorf("option is ilegal: '%s'", resolvline)
				}
			}
			if strings.HasPrefix(op, "timeout:") {
				if _, err := strconv.Atoi(op[8:]); err != nil {
					return fmt.Errorf("option is ilegal: '%s'", resolvline)
				}
			}
			if strings.HasPrefix(op, "attempts:") {
				if _, err := strconv.Atoi(op[9:]); err != nil {
					return fmt.Errorf("option is ilegal: '%s'", resolvline)
				}
			}
		default:
			return fmt.Errorf("ilegal config: '%s'", resolvline)
		}
	}
	return nil
}
