# Packet Sniffer

## How to test
Run a simple (non encrypted) postgres instance
```bash
docker run --rm \
    --name postgres-db \
    -p 5432:5432 \
    -e POSTGRES_USER=userr \
    -e POSTGRES_PASSWORD=paswordd \
    -e POSTGRES_DB=userr \
    postgres:18
```

Get the interface name (should look like "docker0")
```bash
ip address
```

Run the app, passing in interface name (requires running with sudo)
```bash
cargo run -- --interface docker0
```
Can add additional arguments like `source-port-range` and `protocol`

Send a query to the database
```sql
SELECT 1;
```

In the output, you should see your sql query surrounded >>>
The content should be the query sent. Surprisingly, there are other queries sent alongside...

## Caveats
IHL has a min size of 20, max size of 65535, but it didn't seem worth handling large IHLs plus the contents we were after, at least in my testing, had an IHL size of 20. Coulda also did an early return instead of continuing to print.

There's also more granular things like fragment where it uses the first 3 bits to determine fragment.
Postgres have other modes like Parse etc. See [postgresql wire protocol](https://www.postgresql.org/docs/current/protocol-message-formats.html)

## TCP checksum
There exists a thing call "partial checksums" where the tcp checksum will only be calculated from the pseduoheader and not the full thing.
So the tcp checksum in Wireshark is not the final checksum but the partial checksum computed by the OS before the NIC finishes it. Explains why the given checksum and the computed checksum were often quite close...

## TransportLayerProtocol
Messed around with using TryFrom instead of Try and removing Unknown but would make it harder to send information about that because ip header wouldn't have been constructed so ip etc. would need to be returned alongside the error.
TryFrom would be more correct as it should error if the protocol number is unknown.

# Address Resolution Protocol
There's a specific ARP just for Apple??
ARP is not icmp need to find correct protocol number for it
ARP can be used for attacks when a malicious actor could simply respond to a request with their own IP address even if they aren't the intended target

# Filtering maybe to do?
Should really be checked and printed out after it's been sent via the channel rather than before so that concerns about specific ports, ip addresses etc. are handled as part of metrics collection rather than the code that is responsible for collecting and parsing packets
Tho early exits are more efficient...

# Shutting down nicely
`handle_summary` is absolutely fine, there may be a delay of 100ms but that's alright.
`handle_receiving_packets` is not as `rx.next()` is a blocking action and so if no packet ever comes through, then this will block forever and not actually shutdown.
To fix this, can use `rx.try_next()` instead which, if it doesn't receive a packet, it will return `None` allowing for checks to see if it's still running. Downside is using too many cpu cycles, as it continuously loops rather than blocks, which can be mitigated by having thread::sleep but this runs the risk of missing packets.
