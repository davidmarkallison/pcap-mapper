# pcap-mapper

PCAP in, network diagram out: turn your network data into a network diagram.
There will be one node per host (IP + MAC vendor), one edge per host pair, and
it is labelled with the top 3 protocols by packet count.

**Shoutout to [OIDA](https://github.com/f0rw4rd/oida)
by [f0rw4rd](https://github.com/f0rw4rd).** The initial idea for this project came
from wanting an easy, at-a-glance view of OT networks, passively, from pcap data.

**Go check it out.**

## Usage

There is a folder for `.pcap` or `.pcapng` files, just for organisation. Its contents
are in the `.gitignore`.

```
python3 pcap_mapper.py <pcap> [out_basename] [fmt1,fmt2,...] [--collapse-transport]
```

- `out_basename` — output file prefix, default `pcap_map`
- `fmt1,fmt2,...` — graphviz output formats, default `svg,png,pdf`
- `--collapse-transport` — fold an edge's raw TCP/UDP count into its busiest
  app-layer protocol (see below)

Output is `<out_basename>.dot`, and a rendered file per format specified.

Example: `python3 pcap_mapper.py pcaps/capture.pcapng out png,svg`

## Colour Coded Diagram

Each distinct protocol seen in the pcap gets its own colour. 
An edge between two hosts shows up to 3 coloured strands, one per 
protocol, and the label text next to it is coloured to match. 
There is currently no separate legend.

## Node Labels

Each node shows its IP plus the hardware vendor resolved from its MAC
address's OUI (e.g. `Siemens`, `Rockwell`, `WeintekL`).

This leverages tshark's built-in `eth.*_resolved` field and manuf database. 
A host whose MAC never showed up as a src/dst in the capture, or whose OUI
isn't in tshark's database, only shows the IP.

## TCP/UDP vs app-layer protocol

tshark counts each packet under one protocol: the dissected app-layer
protocol when it recognizes one, otherwise the raw transport. So a single
S7COMM session shows up as two separate counts: some packets labelled
`S7COMM`, others (handshake/ACK frames tshark didn't dissect further)
labelled plain `TCP`. That can push `TCP` into the top-3 ahead of the
actual application protocol.

Pass `--collapse-transport` to fold an edge's TCP/UDP packet count into
its busiest app-layer protocol (e.g. `S7COMM (5146) + TCP (2672)` becomes
`S7COMM (7818)`). Edges with no recognized app-layer protocol are left as
plain TCP/UDP, since there's nothing to fold into.

## Requirements

- Python 3
- `tshark` — the Wireshark packet dissector to pull fields out of the pcap
- `dot` — from the `graphviz` package, used to render the `.dot` file

### Installation

```sh
# Debian/Ubuntu (incl. WSL)
sudo apt install tshark graphviz

# macOS
brew install wireshark graphviz

# Fedora
sudo dnf install wireshark-cli graphviz
```

On Debian/Ubuntu, `apt install tshark` may prompt "allow non-root users
to capture packets"; answer either way. This tool only reads existing
pcap files, not live traffic (at this time...).

Ensure both are on PATH: `tshark -v` and `dot -V`.

## Future Work

* Adding icons (selectable) for the nodes:
  * Based on user input?
  * Automated via lookups?
  * Post-generation via GUI?