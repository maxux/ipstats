# Lan Traffic Monitor
Live traffic monitor of your LAN clients from router point of view

# Implementation
This use libpcap to monitor one interface.

Only Ethernet frame with IP packet inside are analyzed. Only the `source`, `destination` and `length`
are read from the packet, the payload is ignored.

This provide a per-second bandwidth usage information about all clients inside
the same interface's network monitored.

# Using the data
By default, only a simple dump on `stdout` is provided.

You can connect a `redis` server where to dump data each second. For each dump, one key per client
will be written, using `traffic-live-[ip]` key and json contents:
```
{
"host": "host1.lan",      // hostname (resolved)
"addr": "10.241.0.201",   // host ip address
"rx": 3781,               // bytes per second in reception
"tx": 9854                // bytes per second in transmission
}
```

# Live example
## Web Based Example
![Web based example](https://i.imgur.com/3WiVHB6.gif)

## Simple Console Dumps
```
[+] initializing lantraffic
---------------------|-----------------|-------------|-----------------
host1.lan            | 10.241.0.201    |   37.8 KB/s |    2.3 KB/s
host2.lan            | 10.241.0.18     |    2.3 KB/s |   37.9 KB/s
---------------------|-----------------|-------------|-----------------
host1.lan            | 10.241.0.201    |  202.0 KB/s |   12.5 KB/s
host2.lan            | 10.241.0.18     |   13.2 KB/s |  204.1 KB/s
```


