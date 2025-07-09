import json
import requests

def mitigate_devices(env, graph, network_id, check_interval=5, quarantine_duration=5):
    """
    Periodically checks (every check_interval seconds) if any device (except 'Router')
    has a latest classification that is not 'normal'. If found, the device is quarantined
    for quarantine_duration seconds. During quarantine, the device's status is set to 'quarantined',
    its node color is set to red (for visibility), and its connection from 'Router' is removed.
    After the quarantine period, the device is restored (status set to 'active', color to blue, and edge re-added).
    """
    while True:
        try:
            response = requests.get(f"http://0.0.0.0:8000/network/{network_id}/packets", timeout=10)
            if response.status_code == 200:
                packets = response.json()
            else:
                print(f"[Mitigation] Failed to get packets: {response.status_code}")
                packets = []
        except Exception as e:
            print(f"[Mitigation] Exception while fetching packets: {e}")
            packets = []

        # Iterate over all devices except "Router"
        for device in list(graph.nodes()):
            if device == "Router":
                continue
            # Get packets for this device; if none, skip.
            device_packets = [p for p in packets if p.get("device") == device]
            if not device_packets:
                continue
            # Get the latest classification
            latest_packet = device_packets[-1]
            classification = latest_packet.get("classification", "normal")
            # If the classification is not 'normal' and device is active, quarantine it.
            if classification != "normal" and graph.nodes[device].get("status") == "active":
                print(f"[Mitigation] Quarantining {device} (classified as {classification})")
                graph.nodes[device]["status"] = "quarantined"
                graph.nodes[device]["color"] = "red"  # Set node color to red
                if graph.has_edge("Router", device):
                    graph.remove_edge("Router", device)
                # Wait for quarantine_duration seconds
                yield env.timeout(quarantine_duration)
                print(f"[Mitigation] Releasing {device} from quarantine")
                graph.nodes[device]["status"] = "active"
                graph.nodes[device]["color"] = "blue"  # Restore default color
                if device in graph.nodes() and not graph.has_edge("Router", device):
                    graph.add_edge("Router", device)
        yield env.timeout(check_interval)




