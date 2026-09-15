"""Built-in well-known port to service-name table (PRD 6.3).

A fixed subset keyed by (port, proto). Deliberately small and offline: flowtest never performs an external
lookup, so an unknown port is simply unnamed (None).

Source: IANA Service Name and Transport Protocol Port Number Registry,
https://www.iana.org/assignments/service-names-port-numbers/ (checked 2026-09-15), plus a handful of
de-facto ports analysts triage daily (SOCKS, Metasploit and Tor defaults, container APIs) that IANA lists
under other names or not at all.

Naming rule: the name a SOC analyst says out loud, lower-case. Where that differs from the IANA name the
IANA name is in a trailing comment. Extend by adding one tuple; keep the list sorted by first port.
"""

from __future__ import annotations

_BOTH = ("tcp", "udp")

# (ports, protocols, name).
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
    ((161,), ("udp",), "snmp"),
    ((162,), ("udp",), "snmptrap"),
    ((179,), ("tcp",), "bgp"),
    ((389,), _BOTH, "ldap"),
    ((443,), _BOTH, "https"),
    ((445,), ("tcp",), "smb"),  # IANA: microsoft-ds
    ((465,), ("tcp",), "smtps"),
    ((500,), ("udp",), "isakmp"),
    ((514,), ("udp",), "syslog"),
    ((587,), ("tcp",), "submission"),
    ((623,), ("udp",), "ipmi"),  # IANA: asf-rmcp
    ((636,), ("tcp",), "ldaps"),
    ((853,), ("tcp",), "dns-over-tls"),  # IANA: domain-s
    ((853,), ("udp",), "dns-over-quic"),  # IANA: domain-s
    ((993,), ("tcp",), "imaps"),
    ((995,), ("tcp",), "pop3s"),
    ((1080,), ("tcp",), "socks"),
    ((1194,), _BOTH, "openvpn"),
    ((1433,), ("tcp",), "mssql"),  # IANA: ms-sql-s
    ((1521,), ("tcp",), "oracle"),  # IANA: ncube-lm; de-facto Oracle TNS listener
    ((1701,), ("udp",), "l2tp"),
    ((1723,), ("tcp",), "pptp"),
    ((1812,), ("udp",), "radius"),
    ((1813,), ("udp",), "radius-acct"),
    ((1883,), ("tcp",), "mqtt"),
    ((1900,), ("udp",), "ssdp"),
    ((2049,), _BOTH, "nfs"),
    ((2375,), ("tcp",), "docker"),  # unencrypted Docker API
    ((2376,), ("tcp",), "docker-tls"),
    ((3128,), ("tcp",), "squid"),  # IANA: ndl-aas; de-facto Squid proxy
    ((3306,), ("tcp",), "mysql"),
    ((3389,), _BOTH, "rdp"),  # IANA: ms-wbt-server
    ((3478,), _BOTH, "stun"),
    ((4444,), ("tcp",), "metasploit"),  # IANA: krb524; de-facto Metasploit default handler
    ((4500,), ("udp",), "ipsec-nat-t"),
    ((5060,), _BOTH, "sip"),
    ((5061,), ("tcp",), "sips"),  # SIP over TLS
    ((5222,), ("tcp",), "xmpp"),  # IANA: xmpp-client
    ((5353,), ("udp",), "mdns"),
    ((5355,), _BOTH, "llmnr"),
    ((5432,), ("tcp",), "postgresql"),
    ((5672,), ("tcp",), "amqp"),
    ((5900,), ("tcp",), "vnc"),  # IANA: rfb
    ((5985,), ("tcp",), "winrm"),  # IANA: wsman
    ((5986,), ("tcp",), "winrm-https"),  # IANA: wsmans
    ((6379,), ("tcp",), "redis"),
    ((6443,), ("tcp",), "kubernetes"),  # de-facto API server; IANA: sun-sr-https
    ((6667,), ("tcp",), "irc"),  # IANA: ircu
    ((8000, 8008, 8080, 8888), ("tcp",), "http-alt"),
    ((8443,), ("tcp",), "https-alt"),  # IANA: pcsync-https
    ((9001,), ("tcp",), "tor-orport"),  # IANA: etlservicemgr; de-facto Tor relay port
    ((9092,), ("tcp",), "kafka"),  # IANA: XmlIpcRegSvc
    ((9200,), ("tcp",), "elasticsearch"),  # IANA: wap-wsp
    ((11211,), _BOTH, "memcached"),
    ((27017,), ("tcp",), "mongodb"),
)

SERVICES: dict[tuple[int, str], str] = {
    (port, proto): name for ports, protos, name in _TABLE for port in ports for proto in protos
}


def service_name(port: int, proto: str) -> str | None:
    """The well-known service on (port, proto), or None when flowtest does not know it."""
    return SERVICES.get((port, proto))
