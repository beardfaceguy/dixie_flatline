FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Host discovery & port scanning
    nmap masscan netdiscover arp-scan fping hping3 unicornscan \
    # Service enumeration
    enum4linux smbclient smbmap nbtscan \
    snmp snmpd snmp-mibs-downloader onesixtyone \
    ldap-utils \
    # Web scanning
    nikto gobuster dirb feroxbuster whatweb wapiti wafw00f \
    curl wget \
    # SSL/TLS
    sslscan sslyze testssl.sh \
    # DNS
    dnsrecon dnsenum fierce dnsutils \
    # Vulnerability assessment
    nuclei exploitdb \
    # Network analysis
    tcpdump tshark netcat-traditional socat traceroute whois \
    # Credential testing
    hydra medusa \
    # Wordlists
    wordlists seclists \
    # Utilities
    python3 python3-pip jq xmlstarlet iproute2 iputils-ping git ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners \
    && git clone --depth 1 https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan \
    && nmap --script-updatedb || true

WORKDIR /workspace
