"""Guest VM: vfkit runtime, host-enforced network gateway, guest bootstrap."""

#: vsock port the guest's sshd bridge listens on. Fixed, because the host has
#: to know where to dial before the guest has told it anything.
VSOCK_SSH_PORT = 2222

#: Preview convention shared by both sides: an app listening on TCP ``P``
#: inside the guest is reachable on vsock port ``P + 40000``. Keeping it a
#: fixed offset means the host never has to ask the guest anything.
VSOCK_FORWARD_BASE = 40000


def vsock_port_for(app_port: int) -> int:
    return VSOCK_FORWARD_BASE + app_port


def app_port_for(vsock_port: int) -> int:
    return vsock_port - VSOCK_FORWARD_BASE
