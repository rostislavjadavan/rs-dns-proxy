# rs-dns-proxy

DNS Proxy with packet inspection PoC.

⚠️ UDP works but TCP resolution is broken. Code is work in progress so it's ugly and contains a lot of weird stuff 😶

## Test queries

```
dig @127.0.0.1 -p 5300 netflix.com
dig @127.0.0.1 +tcp -p 5300 netflix.com
```

## UDP packet vs TCP packet

```
data=[       102, 248, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 7, 110, 101, 116, 102, 108, 105, 120, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0]
data=[0, 40, 199, 214, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 7, 110, 101, 116, 102, 108, 105, 120, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0]
```