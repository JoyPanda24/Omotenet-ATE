import json

from ate.ingestors.traffic_p import TrafficIngestor


LAYERS_WRAPPED_TRAFFIC_DATA = [
    {
        "layers": {
            "frame": {"frame.number": "1"},
            "ip": {
                "ip.src": "192.168.1.100",
                "ip.dst": "10.0.1.50",
                "ip.proto": "6",
            },
            "tcp": {"tcp.srcport": "54321", "tcp.dstport": "80"},
            "http": {
                "http.request.method": "GET",
                "http.request.uri": "/api/users?id=1",
                "http.host": "web.company.com",
            },
            "data": {"data.data": "username=admin password=P@ssw0rd123"},
        }
    }
]


async def test_traffic_ingestor_handles_layers_wrapped_tshark_export(tmp_path):
    export_path = tmp_path / "traffic.json"
    export_path.write_text(json.dumps(LAYERS_WRAPPED_TRAFFIC_DATA), encoding="utf-8")

    ingestor = TrafficIngestor(str(export_path))
    nodes, edges, findings = await ingestor.ingest()

    assert nodes
    assert edges
    assert findings
    assert "192.168.1.100" in nodes
    assert "10.0.1.50" in nodes