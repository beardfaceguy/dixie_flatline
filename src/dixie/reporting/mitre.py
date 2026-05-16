"""MITRE ATT&CK technique catalog for penetration testing findings.

Covers the Enterprise ATT&CK matrix techniques most relevant to pentesting
engagements. Full matrix has 200+ techniques; this is a curated subset with
the ones Dixie will encounter most frequently.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Tactic:
    id: str
    name: str
    description: str


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic_ids: tuple[str, ...]
    description: str = ""
    url: str = ""
    subtechniques: tuple[str, ...] = field(default_factory=tuple)


TACTICS: dict[str, Tactic] = {t.id: t for t in [
    Tactic("TA0043", "Reconnaissance", "Gathering information to plan operations"),
    Tactic("TA0042", "Resource Development", "Establishing resources to support operations"),
    Tactic("TA0001", "Initial Access", "Gaining an initial foothold in a network"),
    Tactic("TA0002", "Execution", "Running adversary-controlled code"),
    Tactic("TA0003", "Persistence", "Maintaining presence across restarts"),
    Tactic("TA0004", "Privilege Escalation", "Gaining higher-level permissions"),
    Tactic("TA0005", "Defense Evasion", "Avoiding detection"),
    Tactic("TA0006", "Credential Access", "Stealing credentials"),
    Tactic("TA0007", "Discovery", "Understanding the environment"),
    Tactic("TA0008", "Lateral Movement", "Moving through the environment"),
    Tactic("TA0009", "Collection", "Gathering data of interest"),
    Tactic("TA0011", "Command and Control", "Communicating with compromised systems"),
    Tactic("TA0010", "Exfiltration", "Stealing data"),
    Tactic("TA0040", "Impact", "Disrupting availability or integrity"),
]}

TECHNIQUES: dict[str, Technique] = {t.id: t for t in [
    # Reconnaissance
    Technique("T1595", "Active Scanning", ("TA0043",),
              url="https://attack.mitre.org/techniques/T1595/",
              subtechniques=("T1595.001", "T1595.002", "T1595.003")),
    Technique("T1595.001", "Scanning IP Blocks", ("TA0043",)),
    Technique("T1595.002", "Vulnerability Scanning", ("TA0043",)),
    Technique("T1595.003", "Wordlist Scanning", ("TA0043",)),
    Technique("T1592", "Gather Victim Host Information", ("TA0043",)),
    Technique("T1590", "Gather Victim Network Information", ("TA0043",)),
    Technique("T1589", "Gather Victim Identity Information", ("TA0043",)),
    Technique("T1591", "Gather Victim Org Information", ("TA0043",)),
    Technique("T1593", "Search Open Websites/Domains", ("TA0043",)),
    Technique("T1596", "Search Open Technical Databases", ("TA0043",)),
    Technique("T1597", "Search Closed Sources", ("TA0043",)),

    # Initial Access
    Technique("T1190", "Exploit Public-Facing Application", ("TA0001",),
              url="https://attack.mitre.org/techniques/T1190/"),
    Technique("T1133", "External Remote Services", ("TA0001", "TA0003")),
    Technique("T1078", "Valid Accounts", ("TA0001", "TA0003", "TA0004", "TA0005")),
    Technique("T1566", "Phishing", ("TA0001",)),
    Technique("T1189", "Drive-by Compromise", ("TA0001",)),
    Technique("T1195", "Supply Chain Compromise", ("TA0001",)),
    Technique("T1199", "Trusted Relationship", ("TA0001",)),

    # Execution
    Technique("T1059", "Command and Scripting Interpreter", ("TA0002",),
              subtechniques=("T1059.001", "T1059.003", "T1059.004")),
    Technique("T1059.001", "PowerShell", ("TA0002",)),
    Technique("T1059.003", "Windows Command Shell", ("TA0002",)),
    Technique("T1059.004", "Unix Shell", ("TA0002",)),
    Technique("T1203", "Exploitation for Client Execution", ("TA0002",)),
    Technique("T1053", "Scheduled Task/Job", ("TA0002", "TA0003", "TA0004")),

    # Persistence
    Technique("T1098", "Account Manipulation", ("TA0003", "TA0004")),
    Technique("T1136", "Create Account", ("TA0003",)),
    Technique("T1505", "Server Software Component", ("TA0003",),
              subtechniques=("T1505.003",)),
    Technique("T1505.003", "Web Shell", ("TA0003",)),
    Technique("T1547", "Boot or Logon Autostart Execution", ("TA0003", "TA0004")),

    # Privilege Escalation
    Technique("T1068", "Exploitation for Privilege Escalation", ("TA0004",),
              url="https://attack.mitre.org/techniques/T1068/"),
    Technique("T1548", "Abuse Elevation Control Mechanism", ("TA0004", "TA0005"),
              subtechniques=("T1548.001", "T1548.003")),
    Technique("T1548.001", "Setuid and Setgid", ("TA0004", "TA0005")),
    Technique("T1548.003", "Sudo and Sudo Caching", ("TA0004", "TA0005")),
    Technique("T1611", "Escape to Host", ("TA0004",)),

    # Defense Evasion
    Technique("T1055", "Process Injection", ("TA0004", "TA0005")),
    Technique("T1070", "Indicator Removal", ("TA0005",)),
    Technique("T1036", "Masquerading", ("TA0005",)),
    Technique("T1027", "Obfuscated Files or Information", ("TA0005",)),
    Technique("T1562", "Impair Defenses", ("TA0005",)),

    # Credential Access
    Technique("T1110", "Brute Force", ("TA0006",),
              subtechniques=("T1110.001", "T1110.003", "T1110.004")),
    Technique("T1110.001", "Password Guessing", ("TA0006",)),
    Technique("T1110.003", "Password Spraying", ("TA0006",)),
    Technique("T1110.004", "Credential Stuffing", ("TA0006",)),
    Technique("T1003", "OS Credential Dumping", ("TA0006",),
              subtechniques=("T1003.001", "T1003.003")),
    Technique("T1003.001", "LSASS Memory", ("TA0006",)),
    Technique("T1003.003", "NTDS", ("TA0006",)),
    Technique("T1558", "Steal or Forge Kerberos Tickets", ("TA0006",),
              subtechniques=("T1558.003",)),
    Technique("T1558.003", "Kerberoasting", ("TA0006",)),
    Technique("T1552", "Unsecured Credentials", ("TA0006",)),
    Technique("T1187", "Forced Authentication", ("TA0006",)),
    Technique("T1557", "Adversary-in-the-Middle", ("TA0006", "TA0009")),
    Technique("T1040", "Network Sniffing", ("TA0006", "TA0007")),

    # Discovery
    Technique("T1046", "Network Service Discovery", ("TA0007",),
              url="https://attack.mitre.org/techniques/T1046/"),
    Technique("T1087", "Account Discovery", ("TA0007",)),
    Technique("T1069", "Permission Groups Discovery", ("TA0007",)),
    Technique("T1018", "Remote System Discovery", ("TA0007",)),
    Technique("T1082", "System Information Discovery", ("TA0007",)),
    Technique("T1083", "File and Directory Discovery", ("TA0007",)),
    Technique("T1016", "System Network Configuration Discovery", ("TA0007",)),
    Technique("T1049", "System Network Connections Discovery", ("TA0007",)),
    Technique("T1482", "Domain Trust Discovery", ("TA0007",)),

    # Lateral Movement
    Technique("T1021", "Remote Services", ("TA0008",),
              subtechniques=("T1021.001", "T1021.002", "T1021.004", "T1021.006")),
    Technique("T1021.001", "Remote Desktop Protocol", ("TA0008",)),
    Technique("T1021.002", "SMB/Windows Admin Shares", ("TA0008",)),
    Technique("T1021.004", "SSH", ("TA0008",)),
    Technique("T1021.006", "Windows Remote Management", ("TA0008",)),
    Technique("T1210", "Exploitation of Remote Services", ("TA0008",)),
    Technique("T1550", "Use Alternate Authentication Material", ("TA0005", "TA0008")),

    # Collection
    Technique("T1005", "Data from Local System", ("TA0009",)),
    Technique("T1039", "Data from Network Shared Drive", ("TA0009",)),
    Technique("T1114", "Email Collection", ("TA0009",)),
    Technique("T1213", "Data from Information Repositories", ("TA0009",)),

    # C2
    Technique("T1071", "Application Layer Protocol", ("TA0011",)),
    Technique("T1095", "Non-Application Layer Protocol", ("TA0011",)),
    Technique("T1572", "Protocol Tunneling", ("TA0011",)),
    Technique("T1090", "Proxy", ("TA0011",)),
    Technique("T1219", "Remote Access Software", ("TA0011",)),

    # Exfiltration
    Technique("T1041", "Exfiltration Over C2 Channel", ("TA0010",)),
    Technique("T1048", "Exfiltration Over Alternative Protocol", ("TA0010",)),
    Technique("T1567", "Exfiltration Over Web Service", ("TA0010",)),

    # Impact
    Technique("T1486", "Data Encrypted for Impact", ("TA0040",)),
    Technique("T1489", "Service Stop", ("TA0040",)),
    Technique("T1499", "Endpoint Denial of Service", ("TA0040",)),
    Technique("T1529", "System Shutdown/Reboot", ("TA0040",)),
]}


def get_technique(technique_id: str) -> Technique | None:
    return TECHNIQUES.get(technique_id)


def get_tactic(tactic_id: str) -> Tactic | None:
    return TACTICS.get(tactic_id)


def tactics_for_technique(technique_id: str) -> list[Tactic]:
    tech = TECHNIQUES.get(technique_id)
    if not tech:
        return []
    return [TACTICS[tid] for tid in tech.tactic_ids if tid in TACTICS]


def techniques_for_tactic(tactic_id: str) -> list[Technique]:
    return [t for t in TECHNIQUES.values() if tactic_id in t.tactic_ids]


def technique_url(technique_id: str) -> str:
    tech = TECHNIQUES.get(technique_id)
    if tech and tech.url:
        return tech.url
    clean = technique_id.replace(".", "/")
    return f"https://attack.mitre.org/techniques/{clean}/"


def resolve_technique_chain(technique_ids: list[str]) -> list[tuple[Technique, list[Tactic]]]:
    """For a list of technique IDs, return (technique, [tactics]) pairs."""
    result = []
    for tid in technique_ids:
        tech = TECHNIQUES.get(tid)
        if tech:
            result.append((tech, tactics_for_technique(tid)))
    return result
