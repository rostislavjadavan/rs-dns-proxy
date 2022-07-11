# rs-dns-proxy

DNS Proxy with packet inspection PoC.

## UDP test

```
dig @127.0.0.1 -p 5300 netflix.com
```

## TCP test

```
ig @127.0.0.1 +tcp -p 5300 netflix.com
```