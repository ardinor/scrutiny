import re
import pyjournalctl

invalid_user_match = "Invalid user (?P<user>.*) from (?P<ip_addr>\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}})"
user_not_allowed = "User (?P<user>.*) from (?P<ip_addr>\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}) not allowed"

reader = pyjournalctl.Journalctl()
reader.this_boot()
reader.add_match("_SYSTEMD_UNIT", "sshd.service")

entry = journal.get_next()

while entry:

    entry_time = entry['__REALTIME_TIMESTAMP']
    match = re.match(invalid_user_match, entry["MESSAGE"])
    if match:
        ip_addr, user = m.group('ip_addr'), m.group('user')

    match = re.match(user_not_allowed, entry["MESSAGE"])
    if match:
         ip_addr, user = m.group('ip_addr'), m.group('user')

    # Add to results

    entry = reader.get_next()



# Sample data from journalctl
# { "__CURSOR" : "s=c2af326eaaf342d796036aade0be5e39;i=5ad;b=19c7e40b44ee4bdcb1d5d3b9138ac21f;m=130ed3d345;t=51332781edcf4;x=71301bf77e8b5442",
#    "__REALTIME_TIMESTAMP" : "1428482368134388",
#    "__MONOTONIC_TIMESTAMP" : "81853141829",
#    "_BOOT_ID" : "19c7e40b44ee4bdcb1d5d3b9138ac21f",
#    "PRIORITY" : "6",
#    "_UID" : "0",
#    "_GID" : "0",
#    "_SYSTEMD_SLICE" : "system.slice",
#    "_MACHINE_ID" : "e30b68561dc94d91be4cf7f8d0c5ed16",
#    "_CAP_EFFECTIVE" : "bdecffff",
#    "_SYSTEMD_UNIT" : "sshd.service",
#    "_TRANSPORT" : "syslog",
#    "SYSLOG_FACILITY" : "10",
#    "SYSLOG_IDENTIFIER" : "sshd",
#    "_COMM" : "sshd",
#    "_EXE" : "/usr/sbin/sshd",
#    "_SYSTEMD_CGROUP" : "/system.slice/sshd.service",
#    "_HOSTNAME" : "letum",
#    "_CMDLINE" : "sshd: unknown [priv]",
#    "MESSAGE" : "User root from 198.143.107.142 not allowed because none of user's groups are listed in AllowGroups",
#    "SYSLOG_PID" : "11697", "_PID" : "11697" }
#     Another message we're interested in
#    "MESSAGE" : "Invalid user mafish from 198.143.107.142"

