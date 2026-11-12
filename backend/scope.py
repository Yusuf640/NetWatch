import ipaddress, os

def check_scope(target: str):
    """Raise ValueError unless the target is private/loopback or explicitly allowed."""
    allowed = [a.strip() for a in os.getenv("NETWATCH_ALLOWED", "").split(",") if a.strip()]
    if target in allowed:
        return
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise ValueError("Hostnames must be listed in NETWATCH_ALLOWED")
    if net.num_addresses > 1024:
        raise ValueError("Range too large (max 1024 addresses)")
    if not (net.is_private or net.is_loopback):
        raise ValueError("Public targets must be listed in NETWATCH_ALLOWED")