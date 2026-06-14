import asyncio
import httpx
import os
import re
import socket

ECP_PORT = 8060

_tv_ip: str | None = os.getenv("HOST_IP")

# Common home network subnets to scan when SSDP (UDP multicast) is unavailable
# (e.g. WSL2 NAT mode blocks multicast but allows TCP through the host).
COMMON_HOME_SUBNETS = [
    "192.168.0.0/24",
    "192.168.1.0/24",
    "10.0.0.0/24",
    "10.0.1.0/24",
]

SSDP_ADDRESS = "239.255.255.250"
SSDP_PORT = 1900
SSDP_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    "Host: 239.255.255.250:1900\r\n"
    'Man: "ssdp:discover"\r\n'
    "ST: roku:ecp\r\n"
    "MX: 3\r\n"
    "\r\n"
)


def _get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _ssdp_scan(timeout: float = 5.0) -> list[dict]:
    """Blocking SSDP scan — run in an executor to avoid blocking the event loop."""
    local_ip = _get_local_ip()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
    # Bind outbound multicast to the correct interface so the packet leaves on the right NIC
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
    # Bind to port 1900 so M-SEARCH responses (and NOTIFY broadcasts) arrive on a known,
    # firewall-friendly port rather than an ephemeral one that Windows blocks.
    sock.bind(("", SSDP_PORT))
    # Join the multicast group to receive NOTIFY announcements as a bonus path.
    try:
        mreq = socket.inet_aton(SSDP_ADDRESS) + socket.inet_aton(local_ip)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass

    sock.settimeout(timeout)
    devices = []
    seen = set()
    try:
        sock.sendto(SSDP_REQUEST.encode(), (SSDP_ADDRESS, SSDP_PORT))
        while True:
            try:
                data, _ = sock.recvfrom(2048)
                response = data.decode(errors="ignore")
                loc = re.search(r"Location:\s*(http://[^\r\n]+)", response, re.IGNORECASE)
                if loc:
                    location = loc.group(1).strip()
                    ip_match = re.search(r"http://([^:/]+)", location)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip not in seen:
                            seen.add(ip)
                            devices.append({"ip": ip, "location": location})
            except socket.timeout:
                break
    finally:
        sock.close()
    return devices


async def _http_scan_subnet(subnet: str, timeout: float = 0.5) -> list[dict]:
    """Probe every host in a /24 subnet for a Roku ECP endpoint over HTTP."""
    import ipaddress
    network = ipaddress.ip_network(subnet, strict=False)

    async def probe(client: httpx.AsyncClient, ip: str) -> dict | None:
        try:
            resp = await client.get(f"http://{ip}:{ECP_PORT}/query/device-info")
            if resp.status_code == 200:
                return {"ip": ip, "location": f"http://{ip}:{ECP_PORT}/"}
        except Exception:
            pass
        return None

    limits = httpx.Limits(max_connections=256, max_keepalive_connections=0)
    async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
        results = await asyncio.gather(*[probe(client, str(ip)) for ip in network.hosts()])
    return [r for r in results if r is not None]


async def discover_roku(timeout: float = 5.0) -> list[dict]:
    """Return a list of Roku devices found via SSDP, falling back to HTTP scan."""
    loop = asyncio.get_event_loop()
    devices = await loop.run_in_executor(None, _ssdp_scan, timeout)
    if devices:
        return devices

    # SSDP failed (common in WSL2 where UDP multicast is blocked at the NAT boundary).
    # Fall back to HTTP probing of common home subnets — TCP routes through the host fine.
    subnets = list(COMMON_HOME_SUBNETS)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        import ipaddress
        local_subnet = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
        if local_subnet not in subnets:
            subnets.insert(0, local_subnet)
    except Exception:
        pass

    for subnet in subnets:
        found = await _http_scan_subnet(subnet)
        if found:
            return found
    return []


async def get_tv_ip() -> str | None:
    """Return the configured or auto-discovered TV IP, caching the result."""
    global _tv_ip
    if _tv_ip is None:
        devices = await discover_roku()
        if devices:
            _tv_ip = devices[0]["ip"]
    return _tv_ip


async def send_ecp_post(command: str) -> bool:
    """Sends a POST request for ECP commands that require an action (e.g., keypress)."""
    ip = await get_tv_ip()
    if not ip:
        return False
    url = f"http://{ip}:{ECP_PORT}/{command}"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(url, data="")
            response.raise_for_status()
            return True
    except (httpx.HTTPError, Exception):
        return False


async def get_device_info() -> str:
    """Retrieves basic device information (model, software version, etc.) as XML."""
    ip = await get_tv_ip()
    if not ip:
        return "No Roku TV found. Ensure the TV is on the same network and 'Control by mobile apps' is enabled."
    url = f"http://{ip}:{ECP_PORT}/query/device-info"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text
    except httpx.HTTPError as e:
        return f"Error retrieving device info from {ip}: {e}. Ensure 'Control by mobile apps' is enabled."
    except Exception as e:
        return f"General Error: {e}"
