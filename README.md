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

Run the app, passing in interface name (requires running with sudo0)
```bash
cargo run -- docker0
```

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
