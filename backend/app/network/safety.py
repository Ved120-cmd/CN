import ipaddress
import socket

MAX_RESOLVED_ADDRESSES = 32

def resolve_public_addresses(host: str) -> list[str]:
    # Intentionally accepts hostnames, not IP literals, and blocks non-public destinations.
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addresses = sorted({str(ipaddress.ip_address(info[4][0])) for info in infos})
    if not addresses:
        raise OSError("Hostname did not resolve to an address")
    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        if (not ip.is_global or ip.is_reserved or ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified):
            raise ValueError("Target resolves to a private, local, or reserved address; use a public host you are authorized to test.")
    if len(addresses) > MAX_RESOLVED_ADDRESSES:
        raise ValueError(f"Target resolved to more than {MAX_RESOLVED_ADDRESSES} addresses; refusing an unbounded probe sequence.")
    return addresses
