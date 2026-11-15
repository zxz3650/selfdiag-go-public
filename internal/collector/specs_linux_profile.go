package collector

func linuxSpecs(profile string) ([]fileSpec, []commandSpec) {
	files := []fileSpec{{"/etc/os-release", "host_info"}, {"/usr/lib/os-release", "host_info"}, {"/proc/version", "host_info"}}
	commands := []commandSpec{{"host_info", []string{"uname", "-a"}}}
	if profile == "triage" || profile == "extended" {
		files = append(files, fileSpec{"/var/log/auth.log", "auth"}, fileSpec{"/var/log/secure", "auth"}, fileSpec{"/var/log/syslog", "event_log"}, fileSpec{"/etc/passwd", "accounts"})
		commands = append(commands, commandSpec{"processes", []string{"ps", "-eo", "pid,ppid,uid,comm"}}, commandSpec{"sockets", []string{"ss", "-an"}}, commandSpec{"services", []string{"systemctl", "list-unit-files", "--no-pager"}})
	}
	return files, commands
}
