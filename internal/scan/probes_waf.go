package scan

// wafClasses are the signature families: twenty-one payload shapes whose only
// purpose is to find out whether a rule fires. Each is addressed to the run's
// probe path, and each has a benign control so a blanket refusal is not
// reported as a rule.
func wafClasses(probePath string) []ProbeClass {
	return []ProbeClass{
		queryClass(StageWAF, "sqli-union", probePath, "id", `1' UNION SELECT password FROM users--`),
		queryClass(StageWAF, "sqli-boolean", probePath, "id", `1' OR '1'='1`),
		queryClass(StageWAF, "sqli-stacked", probePath, "id", `1'; DROP TABLE users--`),
		queryClass(StageWAF, "sqli-comment-obfuscated", probePath, "id", `1'/**/OR/**/1=1--`),

		queryClass(StageWAF, "xss-reflected", probePath, "q", `<script>alert(1)</script>`),
		queryClass(StageWAF, "xss-attribute", probePath, "q", `" onmouseover="alert(1)`),
		queryClass(StageWAF, "xss-javascript-url", probePath, "next", `javascript:alert(1)`),
		queryClass(StageWAF, "xss-svg-event", probePath, "q", `<svg/onload=alert(1)>`),

		queryClass(StageWAF, "cmdi-semicolon", probePath, "host", `127.0.0.1;cat /etc/passwd`),
		queryClass(StageWAF, "cmdi-pipe", probePath, "host", `127.0.0.1|cat /etc/passwd`),
		queryClass(StageWAF, "cmdi-subshell", probePath, "host", `$(cat /etc/passwd)`),
		queryClass(StageWAF, "cmdi-backtick", probePath, "host", "`cat /etc/passwd`"),

		queryClass(StageWAF, "lfi-traversal", probePath, "file", `../../etc/passwd`),
		queryClass(StageWAF, "lfi-file-scheme", probePath, "file", `file:///etc/passwd`),

		queryClass(StageWAF, "ssrf-loopback-url", probePath, "url", `http://127.0.0.1:22/`),
		queryClass(StageWAF, "ssrf-metadata-url", probePath, "url", `http://169.254.169.254/latest/meta-data/`),

		bodyClass(StageWAF, "xxe-body", probePath, "application/xml",
			`<?xml version="1.0"?><d><id>1</id></d>`,
			`<?xml version="1.0"?><!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><d>&e;</d>`),

		headerClass(StageWAF, "log4shell-user-agent", probePath, "User-Agent",
			`${jndi:ldap://127.0.0.1:1389/a}`, scanUserAgent),
		headerClass(StageWAF, "log4shell-header", probePath, "X-Api-Version",
			`${jndi:ldap://127.0.0.1:1389/a}`, "1"),
		headerClass(StageWAF, "log4shell-cookie", probePath, "Cookie",
			`scan=${jndi:ldap://127.0.0.1:1389/a}`, "scan=1"),
		headerClass(StageWAF, "shellshock-user-agent", probePath, "User-Agent",
			`() { :; }; /bin/bash -c id`, scanUserAgent),
	}
}
