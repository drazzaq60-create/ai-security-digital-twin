# ingest_nmap.py
# M4 Step 1: ingest REAL scanner output (an Nmap XML scan) into a clean asset/service inventory.
# Uses Python's built-in XML parser - nothing to install.

import xml.etree.ElementTree as ET


def parse_nmap(path="sample_data/scan.xml"):
    """Parse an Nmap XML file into a list of live hosts, each with its open services."""
    root = ET.parse(path).getroot()
    hosts = []

    for host in root.findall("host"):
        # skip hosts that were down
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr") if addr_el is not None else "unknown"
        name_el = host.find("hostnames/hostname")
        name = name_el.get("name") if name_el is not None else ip

        services = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            services.append({
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "name": svc.get("name") if svc is not None else "unknown",
                "product": svc.get("product") if svc is not None else "",
                "version": svc.get("version") if svc is not None else "",
            })

        hosts.append({"ip": ip, "name": name, "services": services})

    return hosts


if __name__ == "__main__":
    hosts = parse_nmap("sample_data/scan.xml")
    print(f"Discovered {len(hosts)} live host(s):\n")
    for h in hosts:
        print(f"{h['name']} ({h['ip']})")
        for s in h["services"]:
            version = f"{s['product']} {s['version']}".strip()
            print(f"   - {s['port']}/{s['protocol']}  {s['name']}  [{version}]")
        print()
