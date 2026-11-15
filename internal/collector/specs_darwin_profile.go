package collector

func darwinSpecs(profile string) ([]fileSpec, []commandSpec) {
	files := []fileSpec{}
	commands := []commandSpec{{"host_info", []string{"/usr/bin/uname", "-a"}}, {"host_info", []string{"/usr/bin/sw_vers"}}, {"host_info", []string{"/usr/sbin/sysctl", "-n", "hw.machine"}}}
	if profile == "triage" || profile == "extended" {
		commands = append(commands, commandSpec{"processes", []string{"/bin/ps", "-axo", "pid,ppid,uid,comm"}}, commandSpec{"sockets", []string{"/usr/sbin/netstat", "-an"}}, commandSpec{"services", []string{"/bin/launchctl", "list"}})
	}
	return files, commands
}
