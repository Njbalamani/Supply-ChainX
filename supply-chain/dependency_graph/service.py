from __future__ import annotations

from collections import Counter
from typing import Any

import networkx as nx
from django.conf import settings

from config.constants import Severity


def build_networkx_graph(scan) -> nx.DiGraph:
    graph = nx.DiGraph()
    root = f"project:{scan.project_id}"
    graph.add_node(root, kind="project", name=scan.project.name)
    for dep in scan.dependencies.all():
        graph.add_node(
            dep.name,
            kind="package",
            ecosystem=dep.ecosystem,
            version=dep.version,
            is_direct=dep.is_direct,
            purl=dep.purl,
        )
        if dep.is_direct:
            graph.add_edge(root, dep.name, kind="DIRECT", source_file=dep.source_file)
        elif dep.parent_name:
            graph.add_edge(dep.parent_name, dep.name, kind="TRANSITIVE", source_file=dep.source_file)
    return graph


def _vulnerable_names(scan) -> dict[str, str]:
    result: dict[str, str] = {}
    for vuln in scan.vulnerabilities.all():
        current = result.get(vuln.package_name, Severity.UNKNOWN)
        if SEVERITY_ORDER.get(vuln.severity, 0) > SEVERITY_ORDER.get(current, 0):
            result[vuln.package_name] = vuln.severity
    return result


SEVERITY_ORDER = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
SEVERITY_WEIGHT = {
    Severity.UNKNOWN: 2,
    Severity.LOW: 5,
    Severity.MEDIUM: 12,
    Severity.HIGH: 22,
    Severity.CRITICAL: 35,
}


def analyze_graph(scan) -> dict[str, Any]:
    from .models import DependencyEdge, GraphMetric

    graph = build_networkx_graph(scan)
    root = f"project:{scan.project_id}"
    DependencyEdge.objects.filter(scan=scan).delete()
    edge_objects = []
    for source, target, data in graph.edges(data=True):
        edge_objects.append(
            DependencyEdge(
                scan=scan,
                source=source,
                target=target,
                edge_type=data.get("kind", "DIRECT"),
                source_file=data.get("source_file", ""),
            )
        )
    if edge_objects:
        DependencyEdge.objects.bulk_create(edge_objects, ignore_conflicts=True)

    package_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "package"]
    vulnerable = _vulnerable_names(scan)
    vulnerable_paths = []
    for name, severity in vulnerable.items():
        if graph.has_node(name) and nx.has_path(graph, root, name):
            path = nx.shortest_path(graph, root, name)
            vulnerable_paths.append({"package": name, "severity": severity, "path": path})
    vulnerable_paths.sort(key=lambda p: -SEVERITY_ORDER.get(p["severity"], 0))

    depths = []
    for node in package_nodes:
        if nx.has_path(graph, root, node):
            depths.append(nx.shortest_path_length(graph, root, node))
    hubs = sorted(
        ((node, graph.in_degree(node)) for node in package_nodes),
        key=lambda item: -item[1],
    )[:10]

    ecosystem_counter = Counter(
        graph.nodes[node].get("ecosystem", "UNKNOWN") for node in package_nodes
    )
    direct_count = sum(1 for node in package_nodes if graph.nodes[node].get("is_direct"))
    transitive_count = len(package_nodes) - direct_count
    top_hub_share = 0.0
    if hubs and package_nodes:
        top_hub_share = round(hubs[0][1] / max(1, len(package_nodes)), 3)

    concentration = {
        "top_hubs": [{"package": name, "in_degree": degree} for name, degree in hubs],
        "top_hub_share": top_hub_share,
        "ecosystems": dict(ecosystem_counter),
        "direct_count": direct_count,
        "transitive_count": transitive_count,
        "max_depth": max(depths) if depths else 0,
        "cycles": [cycle for cycle in nx.simple_cycles(graph) if root not in cycle][:10],
    }

    vuln_weight = sum(SEVERITY_WEIGHT.get(sev, 2) for sev in vulnerable.values())
    depth_weight = min(20, (max(depths) if depths else 0) * 3)
    concentration_weight = min(15, round(top_hub_share * 50))
    risk_score = min(100, vuln_weight + depth_weight + concentration_weight)

    metric, _ = GraphMetric.objects.update_or_create(
        scan=scan,
        defaults={
            "node_count": len(package_nodes),
            "edge_count": graph.number_of_edges(),
            "vulnerable_node_count": len(vulnerable),
            "direct_count": direct_count,
            "transitive_count": transitive_count,
            "max_depth": max(depths) if depths else 0,
            "vulnerable_paths": vulnerable_paths,
            "concentration": concentration,
            "risk_score": risk_score,
        },
    )
    return {
        "node_count": metric.node_count,
        "edge_count": metric.edge_count,
        "vulnerable_node_count": metric.vulnerable_node_count,
        "risk_score": metric.risk_score,
        "vulnerable_paths": vulnerable_paths[:25],
    }


def graph_payload(scan) -> dict:
    graph = build_networkx_graph(scan)
    vulnerable = _vulnerable_names(scan)
    nodes = []
    for node, data in graph.nodes(data=True):
        nodes.append(
            {
                "id": node,
                "label": data.get("name", node),
                "kind": data.get("kind", "package"),
                "ecosystem": data.get("ecosystem", ""),
                "version": data.get("version", ""),
                "severity": vulnerable.get(node, "UNKNOWN"),
                "purl": data.get("purl", ""),
            }
        )
    edges = [
        {"source": source, "target": target, "kind": data.get("kind", "DIRECT")}
        for source, target, data in graph.edges(data=True)
    ]
    return {"nodes": nodes, "edges": edges, "vulnerable": vulnerable}
