"""Built-in well-known port to service-name table (PRD 6.3).

A fixed subset of the IANA registry, keyed by (port, proto). Deliberately small and offline: flowtest never
performs an external lookup, so an unknown port is simply unnamed (None).
"""

from __future__ import annotations

_BOTH = ("tcp", "udp")

# (ports, protocols, name). Names are lower-case IANA short names as analysts usually write them.
_TABLE: tuple[tuple[tuple[int, ...], tuple[str, ...], str], ...] = (
    ((20,), ("tcp",), "ftp-data"),
    ((21,), ("tcp",), "ftp"),
    ((22,), ("tcp",), "ssh"),
    ((23,), ("tcp",), "telnet"),
    ((25,), ("tcp",), "smtp"),
    ((53,), _BOTH, "dns"),
    ((67, 68), ("udp",), "dhcp"),
    ((69,), ("udp",), "tftp"),
    ((80,), ("tcp",), "http"),
    ((88,), _BOTH, "kerberos"),
    ((110,), ("tcp",), "pop3"),
    ((111,), _BOTH, "rpcbind"),
    ((123,), ("udp",), "ntp"),
    ((135,), _BOTH, "msrpc"),
    ((137, 138), ("udp",), "netbios"),
    ((139,), ("tcp",), "netbios-ssn"),
    ((143,), ("tcp",), "imap"),
    ((161, 162), ("udp",), "snmp"),
    ((179,), ("tcp",), "bgp"),
    ((389,), _BOTH, "ldap"),
    ((443,), _BOTH, "https"),
    ((445,), ("tcp",), "smb"),
    ((465,), ("tcp",), "smtps"),
    ((500,), ("udp",), "isakmp"),
    ((514,), ("udp",), "syslog"),
    ((587,), ("tcp",), "submission"),
    ((636,), ("tcp",), "ldaps"),
    ((853,), _BOTH, "dns-over-tls"),
    ((993,), ("tcp",), "imaps"),
    ((995,), ("tcp",), "pop3s"),
    ((1194,), _BOTH, "openvpn"),
    ((1433,), ("tcp",), "mssql"),
    ((1521,), ("tcp",), "oracle"),
    ((1723,), ("tcp",), "pptp"),
    ((1812, 1813), ("udp",), "radius"),
    ((1883,), ("tcp",), "mqtt"),
    ((2049,), _BOTH, "nfs"),
    ((3128,), ("tcp",), "squid"),
    ((3306,), ("tcp",), "mysql"),
    ((3389,), _BOTH, "rdp"),
    ((4500,), ("udp",), "ipsec-nat-t"),
    ((5060, 5061), _BOTH, "sip"),
    ((5222,), ("tcp",), "xmpp"),
    ((5432,), ("tcp",), "postgresql"),
    ((5900,), ("tcp",), "vnc"),
    ((5985, 5986), ("tcp",), "winrm"),
    ((6379,), ("tcp",), "redis"),
    ((8080,), ("tcp",), "http-alt"),
    ((8443,), ("tcp",), "https-alt"),
    ((9200,), ("tcp",), "elasticsearch"),
    ((27017,), ("tcp",), "mongodb"),
)

SERVICES: dict[tuple[int, str], str] = {
    (port, proto): name for ports, protos, name in _TABLE for port in ports for proto in protos
}


def service_name(port: int, proto: str) -> str | None:
    """The well-known service on (port, proto), or None when flowtest does not know it."""
    return SERVICES.get((port, proto))
