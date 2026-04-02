# Copilot Instructions for sonic-frr

## Project Overview

sonic-frr is SONiC's fork of FRRouting (FRR), the open-source IP routing protocol suite. It provides BGP, OSPF, IS-IS, PIM, BFD, LDP, PBR, Babel, EIGRP, NHRP, and other routing protocol implementations. SONiC uses FRR as its routing stack, with FPM (Forwarding Plane Manager) integration to push routes into the SONiC data plane via fpmsyncd.

## Architecture

```
sonic-frr/
├── bgpd/               # BGP daemon implementation
├── ospfd/               # OSPFv2 daemon
├── ospf6d/              # OSPFv3 daemon
├── isisd/               # IS-IS daemon
├── pimd/                # PIM-SM/SSM daemon
├── bfdd/                # BFD daemon
├── ldpd/                # LDP daemon
├── pbrd/                # PBR daemon
├── staticd/             # Static route daemon
├── babeld/              # Babel daemon
├── eigrpd/              # EIGRP daemon (alpha)
├── nhrpd/               # NHRP daemon (alpha)
├── zebra/               # Core routing daemon (RIB, FPM, kernel integration)
├── lib/                 # Shared libraries (vty, thread, prefix, etc.)
├── vtysh/               # VTY shell (CLI)
├── yang/                # YANG models for routing protocols
├── tests/               # Test suite
├── doc/                 # Documentation (Sphinx)
├── debian/              # Debian packaging
├── bootstrap.sh         # Autotools bootstrap
├── configure.ac         # Autoconf configuration
└── Makefile.am          # Automake build rules
```

### Key Concepts
- **Zebra**: Central daemon managing the RIB (Routing Information Base) and kernel route installation
- **FPM (Forwarding Plane Manager)**: Interface to push routes to external consumers (SONiC's fpmsyncd)
- **VTY**: Virtual terminal interface — the CLI for configuring routing protocols
- **Zserv**: Internal protocol for communication between routing daemons and zebra
- **YANG models**: Data models for protocol configuration and state

## Language & Style

- **Primary language**: C (core daemons), Python (tests, scripts)
- **C standard**: C11
- **Indentation**: Tabs (kernel style) in C code
- **Naming conventions**:
  - Functions: `module_action_object` (e.g., `bgp_route_add`, `ospf_lsa_install`)
  - Structs: `struct bgp_info`, `struct ospf_area`
  - Macros: `UPPER_CASE`
  - Enums: `UPPER_CASE` values
- **Code formatting**: Follow existing FRR style — see `.clang-format`
- **Memory management**: Use FRR's memory tracking macros (`XMALLOC`, `XFREE`, `MTYPE_*`)
- **Threading**: FRR uses an event-driven model with `struct thread_master` — avoid blocking calls
- **Logging**: Use `zlog_*` macros (e.g., `zlog_info`, `zlog_warn`, `zlog_err`)

## Build Instructions

```bash
# Bootstrap autotools
./bootstrap.sh

# Configure (typical SONiC build configuration)
./configure \
  --prefix=/usr \
  --sysconfdir=/etc/frr \
  --localstatedir=/var/run/frr \
  --enable-fpm \
  --enable-multipath=64

# Build
make -j$(nproc)

# Install
sudo make install

# Build Debian package
dpkg-buildpackage -rfakeroot -b -us -uc
```

## Testing

```bash
# Run unit tests
make check

# Run topotests (topology-based integration tests)
cd tests/topotests
sudo pytest -v

# Individual protocol tests
sudo pytest tests/topotests/bgp_* -v
```

### Test Types
- **Unit tests**: In `tests/` — test individual functions and data structures
- **Topotests**: Topology-based integration tests using Mininet-like environments
- **VTY tests**: Test CLI command parsing and configuration

## PR Guidelines

- **Signed-off-by**: Required on all commits
- **CLA**: Sign Linux Foundation EasyCLA (for SONiC changes)
- **Upstream FRR**: Consider whether changes should also be submitted upstream to FRRouting/frr
- **SONiC-specific patches**: Clearly separate SONiC-specific patches from upstream FRR code
- **Commit message**: Reference the FRR module: `bgpd:`, `zebra:`, `ospfd:`, etc.
- **Testing**: Include topotests for new protocol features

## Dependencies

- **libyang**: YANG data modeling library
- **json-c**: JSON parsing
- **readline**: CLI line editing
- **libcap**: Linux capabilities
- **protobuf-c**: Protocol Buffers for FPM
- **libnl**: Netlink communication

## Gotchas

- **FPM integration**: SONiC relies heavily on FPM — changes to zebra's FPM code directly affect route programming
- **SONiC fork divergence**: This fork carries SONiC-specific patches on top of upstream FRR; rebase carefully
- **Event loop**: All daemons use FRR's event loop — never block in callbacks
- **Memory types**: Register new memory types with `MTYPE_*` macros for leak detection
- **VTY commands**: Follow the `DEFUN`/`DEFPY` macro pattern for new CLI commands
- **Thread safety**: FRR daemons are largely single-threaded per process — the event-driven model handles concurrency
- **YANG models**: New configuration should include YANG model definitions
- **Route redistribution**: Changes to route redistribution affect the entire routing stack
