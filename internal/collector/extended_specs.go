package collector

import "fmt"

type treeSpec struct {
	Path       string   `json:"path"`
	Kind       string   `json:"kind"`
	MaxEntries int      `json:"max_entries"`
	MaxDepth   int      `json:"max_depth"`
	Suffixes   []string `json:"suffixes,omitempty"`
}

func specsForOS(osName, profile string) ([]fileSpec, []commandSpec, []treeSpec) {
	var files []fileSpec
	var commands []commandSpec
	var trees []treeSpec
	if osName == "linux" {
		files, commands = linuxSpecs(profile)
	} else {
		files, commands = darwinSpecs(profile)
	}
	if profile != "extended" {
		return files, commands, trees
	}
	addFiles := func(kind string, paths ...string) {
		for _, p := range paths {
			files = append(files, fileSpec{p, kind})
		}
	}
	addCmd := func(kind string, args ...string) { commands = append(commands, commandSpec{kind, args}) }
	addTree := func(kind string, paths ...string) {
		for _, p := range paths {
			trees = append(trees, treeSpec{Path: p, Kind: kind, MaxEntries: 64, MaxDepth: 5})
		}
	}
	if osName == "linux" {
		addFiles("accounts", "/etc/group", "/etc/nsswitch.conf")
		addFiles("storage", "/etc/fstab", "/proc/partitions", "/proc/mounts")
		addFiles("network_config", "/etc/hosts", "/etc/hosts.allow", "/etc/hosts.deny", "/etc/network/interfaces", "/etc/resolv.conf")
		addFiles("login_binary", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/run/utmp")
		addFiles("persistence", "/etc/crontab", "/etc/rc.local", "/etc/profile", "/etc/ld.so.preload")
		addCmd("host_info", "date", "--iso-8601=seconds")
		addCmd("host_info", "uptime")
		addCmd("host_info", "lscpu")
		addCmd("kernel_log", "dmesg")
		addCmd("processes", "ps", "-eo", "pid,ppid,uid,lstart,args")
		addCmd("modules", "lsmod")
		addCmd("process_metrics", "vmstat")
		addCmd("open_files", "lsof", "-nP", "-w")
		addCmd("sockets", "ss", "-anp")
		addCmd("bpf_sockets", "ss", "-0bp")
		addCmd("network_interfaces", "ip", "address", "show")
		addCmd("routes", "ip", "route", "show")
		addCmd("neighbors", "ip", "neigh", "show")
		addCmd("login_sessions", "who", "-a")
		addCmd("login_sessions", "w")
		addCmd("login_history", "last", "-n", "100")
		addCmd("login_history", "lastb", "-n", "100")
		addCmd("login_history", "lastlog")
		addCmd("storage", "df", "-h")
		addCmd("storage", "lsblk", "-J")
		addCmd("storage", "blkid")
		addCmd("packages", "dpkg-query", "-W")
		addCmd("packages", "rpm", "-qa")
		addCmd("services", "systemctl", "list-units", "--all", "--no-pager")
		addCmd("journal", "journalctl", "--no-pager", "-n", "1000", "-o", "short-iso")
		addTree("persistence", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/etc/init.d", "/etc/systemd/system", "/usr/lib/systemd/system", "/etc/profile.d")
		addTree("logs", "/var/log")
		addTree("config", "/etc/ssh", "/etc/pam.d", "/etc/sudoers.d", "/etc/apache2", "/etc/nginx", "/etc/php", "/etc/mysql", "/etc/postgresql")
		addFiles("config", "/etc/sudoers")
		for _, p := range []string{"/var/www", "/srv/www"} {
			trees = append(trees, treeSpec{Path: p, Kind: "web_source", MaxEntries: 64, MaxDepth: 5, Suffixes: []string{".php", ".jsp", ".jspx", ".html", ".js"}})
		}
	} else {
		addFiles("accounts", "/etc/passwd", "/etc/group")
		addFiles("network_config", "/etc/hosts", "/etc/resolv.conf")
		addFiles("persistence", "/etc/crontab", "/etc/rc.common", "/etc/profile", "/etc/zprofile", "/etc/zshrc")
		addCmd("host_info", "/usr/bin/uptime")
		addCmd("accounts", "/usr/bin/dscl", ".", "-list", "/Users", "UniqueID")
		addCmd("processes", "/bin/ps", "-axo", "pid,ppid,uid,lstart,command")
		addCmd("open_files", "/usr/sbin/lsof", "-nP")
		addCmd("network_interfaces", "/sbin/ifconfig", "-a")
		addCmd("routes", "/usr/sbin/netstat", "-rn")
		addCmd("neighbors", "/usr/sbin/arp", "-an")
		addCmd("login_sessions", "/usr/bin/who", "-a")
		addCmd("login_sessions", "/usr/bin/w")
		addCmd("login_history", "/usr/bin/last", "-10")
		addCmd("storage", "/bin/df", "-h")
		addCmd("storage", "/usr/sbin/diskutil", "list", "-plist")
		addCmd("packages", "/usr/sbin/pkgutil", "--pkgs")
		addCmd("services", "/bin/launchctl", "print", "system")
		addCmd("system_extensions", "/usr/bin/systemextensionsctl", "list")
		addCmd("unified_log", "/usr/bin/log", "show", "--last", "1h", "--style", "json", "--predicate", "process == \"sshd\" OR process == \"sudo\" OR process == \"loginwindow\"")
		addTree("persistence", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/System/Library/LaunchAgents", "/System/Library/LaunchDaemons", "/private/etc/periodic", "/private/var/at/tabs")
		addTree("logs", "/private/var/log")
		addTree("config", "/private/etc/ssh", "/private/etc/pam.d")
	}
	return files, commands, trees
}

// Plan lists static selectors without reading a target filesystem or running commands.
func Plan(osName, profile string) (map[string]any, error) {
	if osName != "linux" && osName != "darwin" {
		return nil, fmt.Errorf("source OS must be linux or darwin")
	}
	if profile != "system" && profile != "triage" && profile != "extended" {
		return nil, fmt.Errorf("unknown profile")
	}
	files, commands, trees := specsForOS(osName, profile)
	f := []map[string]string{}
	c := []map[string]any{}
	for _, s := range files {
		f = append(f, map[string]string{"path": s.path, "kind": s.kind})
	}
	for _, s := range commands {
		c = append(c, map[string]any{"argv": s.args, "kind": s.kind})
	}
	return map[string]any{"source_os": osName, "profile": profile, "files": f, "commands": c, "trees": trees,
		"dynamic": "extended: bounded user homes and Linux /proc; optional browser databases, environments/shadow, executable bytes", "limits": "512 artifacts / 64 MiB total / 8 MiB per file; bounded selectors may collect only a subset"}, nil
}
