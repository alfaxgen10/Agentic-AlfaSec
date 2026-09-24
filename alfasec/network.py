"""Authorized loopback network checks."""
from __future__ import annotations
import socket
def authorized_host(host: str, allowlist: set[str]) -> bool:
    if host in allowlist:
        return True
    try:
        address = socket.gethostbyname(host)
        return address.startswith("127.") or address == "::1"
    except socket.gaierror:
        return False

def port_scan(host: str, start: int, end: int, allowlist: set[str]) -> dict:
    if not authorized_host(host, allowlist) or not (1 <= start <= end <= 65535) or end - start > 255:
        raise ValueError("Target must be allowlisted/loopback and the range must contain at most 256 ports.")
    open_ports = []
    for port in range(start, end + 1):
        with socket.socket() as sock:
            sock.settimeout(0.25)
            try:
                sock.connect((host, port))
                open_ports.append(port)
            except OSError:
                pass
    return {"host": host, "start": start, "end": end, "open_ports": open_ports}
