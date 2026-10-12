#!/usr/bin/env python3
"""pcap -> network diagram. Edges = undirected host pairs, labelled with top-3 protocols by packet count.

Usage: pcap_mapper.py <pcap> [out_basename] [-Tpng,svg,pdf]
"""
import subprocess
import sys
from collections import Counter, defaultdict
from xml.sax.saxutils import escape

FORMATS = ("svg", "png", "pdf")
TRANSPORT = {"TCP", "UDP"}
# ColorBrewer Set1/Paired, distinct & readable on white
PALETTE = [
    "#e41a1c", "#377eb8", "#4daf4a", "#984ea3", "#ff7f00",
    "#a65628", "#f781bf", "#999999", "#1b9e77", "#d95f02",
]


def _vendor(resolved):
    """'WeintekL_2b:79:c4' -> 'WeintekL'; unresolved MACs (no vendor prefix) -> None."""
    return resolved.rsplit("_", 1)[0] if "_" in resolved else None


def extract_edges(pcap_path):
    cmd = [
        "tshark", "-r", pcap_path, "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
        "-e", "eth.src_resolved", "-e", "eth.dst_resolved",
        "-E", "separator=\t", "-E", "quote=n",
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    edges = defaultdict(Counter)
    vendor_votes = defaultdict(Counter)
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or not parts[0] or not parts[1]:
            continue  # skip non-IP frames (ARP etc.)
        src, dst, proto, src_eth, dst_eth = parts
        edge = tuple(sorted((src, dst)))  # undirected: a<->b traffic on one edge
        edges[edge][proto] += 1
        if (v := _vendor(src_eth)):
            vendor_votes[src][v] += 1
        if (v := _vendor(dst_eth)):
            vendor_votes[dst][v] += 1
    vendors = {ip: votes.most_common(1)[0][0] for ip, votes in vendor_votes.items()}
    return edges, vendors


def collapse_transport(edges):
    """Fold an edge's raw TCP/UDP packet counts into its busiest app-layer protocol."""
    for protos in edges.values():
        app_protos = [p for p in protos if p not in TRANSPORT]
        if not app_protos:
            continue
        top_app = max(app_protos, key=protos.get)
        for t in TRANSPORT:
            if t in protos:
                protos[top_app] += protos.pop(t)
    return edges


def assign_colors(edges):
    totals = Counter()
    for protos in edges.values():
        totals.update(protos)
    ranked = [p for p, _ in totals.most_common()]
    return {p: PALETTE[i % len(PALETTE)] for i, p in enumerate(ranked)}


def write_dot(edges, vendors, dot_path):
    colors = assign_colors(edges)
    lines = [
        "graph pcap {",
        '  layout="dot";',  # rank-based layout crosses far fewer lines than force-directed (neato/fdp) on hub-and-spoke pcap graphs
        "  splines=true;",
        '  nodesep="0.6";',
        '  ranksep="0.9";',
        "  node [shape=box, fontsize=10];",
    ]
    hosts = sorted({ip for edge in edges for ip in edge})
    for ip in hosts:
        label = f"{ip}\\n{vendors[ip]}" if ip in vendors else ip
        lines.append(f'  "{escape(ip)}" [label="{escape(label)}"];')
    for (a, b), protos in edges.items():
        top3 = protos.most_common(3)
        edge_colors = [colors[p] for p, _ in top3]
        color_attr = ":".join(edge_colors)
        html_label = "<" + "<br/>".join(
            f'<font color="{c}">{escape(p)} ({n})</font>' for (p, n), c in zip(top3, edge_colors)
        ) + ">"
        lines.append(
            f'  "{escape(a)}" -- "{escape(b)}" [label={html_label}, color="{color_attr}", penwidth=2, fontsize=9];'
        )
    lines.append("}")
    with open(dot_path, "w") as f:
        f.write("\n".join(lines))


def render(dot_path, out_base, formats):
    for fmt in formats:
        subprocess.run(["dot", f"-T{fmt}", dot_path, "-o", f"{out_base}.{fmt}"], check=True)


def main():
    args = sys.argv[1:]
    collapse = "--collapse-transport" in args
    if collapse:
        args.remove("--collapse-transport")

    if len(args) < 1:
        sys.exit(f"usage: {sys.argv[0]} <pcap> [out_basename] [fmt1,fmt2,...] [--collapse-transport]")
    pcap_path = args[0]
    out_base = args[1] if len(args) > 1 else "pcap_map"
    formats = args[2].split(",") if len(args) > 2 else list(FORMATS)

    edges, vendors = extract_edges(pcap_path)
    if collapse:
        edges = collapse_transport(edges)
    dot_path = f"{out_base}.dot"
    write_dot(edges, vendors, dot_path)
    render(dot_path, out_base, formats)
    print(f"{len(edges)} edges -> {dot_path}, " + ", ".join(f"{out_base}.{f}" for f in formats))


if __name__ == "__main__":
    main()
