import re, sys

thread = {
    "internal/api/account.go": ["consumeRecoveryCode"],
    "internal/api/audit_snapshots.go": ["snapshotProxy", "snapshotPolicy", "snapshotProfile",
                                        "snapshotProtectionProfile", "snapshotAccessProfile",
                                        "snapshotAccessList", "auditChange", "restoreSnapshot"],
    "internal/api/bundles.go": ["bundleSnapshot"],
    "internal/api/config_yaml.go": ["configDocument", "applyWAFProfiles", "applyProtectionProfiles",
                                    "applyAccessLists", "applyConfigPolicies", "applyConfigProxies",
                                    "linkConfigProxyAccessProfiles", "applyAccessProfiles"],
    "internal/api/global_profile.go": ["globalListAttached"],
    "internal/api/handlers.go": ["inheritAccessProfile", "checkAuthProvider", "saveChildren", "validateHostname"],
    "internal/api/header_audit.go": ["protectionProfileFor"],
    "internal/api/incident_report.go": ["reportAudit"],
    "internal/api/profiles_extra.go": ["validateAccessProfile", "validateAccessPolicies"],
    "internal/api/restore.go": ["applySettings", "applyProxies", "applyPolicies"],
    "internal/api/server.go": ["cleanDecoyHosts"],
    "internal/api/streaming.go": ["streamingLists", "streamListUsers"],
}

hostwide = {
    "internal/api/auto_update.go": ["autoUpdateSettings", "runAutoUpdate"],
    "internal/api/crowdsec.go": ["storedCrowdSec", "saveCrowdSecConfig"],
    "internal/api/rbac.go": ["loadAdminAllowlist"],
}


def span(lines, name):
    start = None
    for i, l in enumerate(lines):
        if l.startswith("func (s *Server) " + name + "("):
            start = i
            break
    if start is None:
        print("!! no func", name)
        sys.exit(1)
    for j in range(start + 1, len(lines)):
        if lines[j] == "}\n":
            return start, j
    print("!! no end", name)
    sys.exit(1)


for path, names in hostwide.items():
    lines = open(path).readlines()
    for name in names:
        a, b = span(lines, name)
        for i in range(a, b):
            lines[i] = lines[i].replace("s.db(r).", "s.st.")
    open(path, "w").writelines(lines)
    print("reverted", path, len(names))

for path, names in thread.items():
    lines = open(path).readlines()
    for name in names:
        a, b = span(lines, name)
        head = lines[a]
        if "_ *http.Request" in head:
            lines[a] = head.replace("_ *http.Request", "r *http.Request")
            continue
        body = lines[a:b]
        text = "".join(body)
        text = text.replace("s.db(r).", "s.db(r).")
        lines[a:b] = [text]
        # insert r as the first parameter after the receiver
        m = re.match(r"(func \(s \*Server\) " + name + r"\()(.*)(\).*\n)", lines[a], re.S)
        if not m:
            print("!! signature", path, name)
            sys.exit(1)
        inside = m.group(2)
        new = "r *http.Request" if inside == "" else "r *http.Request, " + inside
        lines[a] = m.group(1) + new + m.group(3)
    open(path, "w").writelines(lines)
    print("threaded", path, len(names))

# Call sites: s.name(  ->  s.name(r, ...) or s.name(r) when empty.
import glob
names = [n for v in thread.values() for n in v]
for path in glob.glob("internal/api/*.go"):
    s = open(path).read()
    orig = s
    for n in names:
        s = re.sub(r"\bs\." + n + r"\(\)", "s." + n + "(r)", s)
        s = re.sub(r"\bs\." + n + r"\((?!r\))", "s." + n + "(r, ", s)
    if s != orig:
        open(path, "w").write(s)
        print("callsites", path)
