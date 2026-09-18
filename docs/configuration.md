# Configuration Reference

`vpnfront` accepts strict YAML or JSON configuration. Unknown fields are rejected. Validate a file before using it:

```sh
go run ./cmd/vpnfront --validate-config /path/to/proxy.yaml
```

A valid file prints `configuration valid`; malformed or unsafe configuration exits with status 2.

## Minimal loopback listener

```yaml
listeners:
  - id: local-socks
    protocol: socks5
    host: 127.0.0.1
    port: 1080
    profile: corp

profiles:
  - id: corp
    backend: ssh
```

`host`, `port`, `auth.type`, `acl.defaultAction`, and `shutdownTimeout` default to `127.0.0.1`, `1080`, `none`, `allow`, and `30s` respectively for loopback listeners.

`shutdownTimeout` is a positive Go duration such as `15s` or `2m`. When the daemon is asked to stop without a caller-supplied deadline, it waits up to this duration for active connections, then closes them.

## Public or LAN listener requirements

A non-loopback listener must declare all of:

- `tls.certFile` and `tls.keyFile`
- Either Basic proxy authentication or `tls.requireClientCertificate: true`
- `acl.sourceCidrs`
- An explicit destination allow-list or deny-by-default policy

```yaml
listeners:
  - id: lan-http
    protocol: http
    host: 0.0.0.0
    port: 8443
    profile: corporate
    tls:
      certFile: /etc/vpnfront/server.crt
      keyFile: /etc/vpnfront/server.key
      clientCAFile: /etc/vpnfront/clients.crt
      requireClientCertificate: true
    auth:
      type: basic
      username: proxy-user
      passwordEnv: VPNFRONT_PROXY_PASSWORD
      realm: corporate-proxy
    acl:
      defaultAction: deny
      sourceCidrs:
        - 10.20.0.0/16
      allowCidrs:
        - 10.0.0.0/8
      allowDomains:
        - internal.example

profiles:
  - id: corporate
    backend: wireguard
    mode: attached-interface
    interface: wg0
```

Do not place passwords, private keys, OpenVPN profiles, or WireGuard configurations in this file. `passwordEnv` names an environment variable whose value is read only at daemon construction and is never logged.

## Attached OpenVPN and WireGuard profiles

M4 uses an already-established operating-system VPN interface. It does not launch a GUI or native VPN process and does not create routes. The profile must use `mode: attached-interface` and provide either an interface name or an explicit local address:

```yaml
profiles:
  - id: corp-wireguard
    backend: wireguard
    mode: attached-interface
    interface: wg0
    dns:
      mode: remote-tcp
      servers:
        - 10.0.0.53:53

  - id: corp-openvpn
    backend: openvpn
    mode: attached-interface
    localAddress: 10.8.0.2
    dns:
      mode: tunnel
      servers:
        - 10.8.0.1:53
```

TCP sockets bind their local address to the selected interface address. UDP associations bind packet sockets the same way. If an interface is missing, down, or has no usable address, connector construction fails; there is no direct-egress fallback.

`dns.mode` must be explicit when DNS resolution is needed. Supported modes are `remote-tcp` and `tunnel`, both requiring `dns.servers`. If no tunnel DNS server is configured, hostname resolution fails closed instead of using the host operating system resolver.


A listener has a fixed `profile` or ordered `routes`. Rules are evaluated in order:

```yaml
listeners:
  - id: routed-socks
    protocol: socks5
    host: 127.0.0.1
    port: 1080
    routes:
      - cidr: 10.0.0.0/8
        profile: corporate
      - domainSuffix: .internal.example
        profile: corporate
      - default: true
        profile: privacy

profiles:
  - id: corporate
    backend: wireguard
    mode: attached-interface
    interface: wg0
  - id: privacy
    backend: openvpn
    mode: attached-interface
    localAddress: 10.9.0.2
```

CIDR rules apply only to IP-literal destinations. Hostname routing should use `domainSuffix`; resolving arbitrary hostnames locally merely to select a CIDR route can leak DNS. There may be only one default route.

## Protocol authentication

- HTTP uses `Proxy-Authorization: Basic …` and responds with `407 Proxy Authentication Required` when credentials are missing or invalid.
- SOCKS5 uses RFC 1929 username/password negotiation when `auth.type: basic` is configured.
- SOCKS4 has no password authentication; use mutual TLS for an authenticated non-loopback SOCKS4 listener.

## Destination protection

Destination ACLs evaluate explicit denies, then explicit allows, then the default action. The AWS IPv4 metadata endpoint (`169.254.169.254`) and IPv6 link-local range are always denied. HTTP forward-proxy requests remove `Proxy-Authorization` before they are sent upstream.

## Current scope

M4 provides strict configuration validation for attached VPN profiles, policy construction, TLS/mTLS listener setup, authentication, dynamic profile selection, daemon lifecycle, and interface-bound OpenVPN/WireGuard TCP/UDP/DNS egress. M5 will add managed native VPN client processes.
