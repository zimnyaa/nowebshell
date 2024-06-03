# `nowebshell`

```
explained at tishina.in/ops/pidfd-getfd-shell
```

```
The PoC is a simple bind shell with SOCKS5 capabilities 
that hijacks incoming connections to TCP services instead 
of listening on its own. It does this by scanning the `/proc` 
filesystem for connections from whitelisted IPs and using the 
`pidfd_getfd` Linux syscall to duplicate the file descriptor 
for the connection.
```