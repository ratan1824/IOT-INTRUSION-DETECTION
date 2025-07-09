# ------------------------------------------------------------------------
# library imports
# ------------------------------------------------------------------------

import time
from collections import deque
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from datetime import datetime
from typing import Dict, Any
import secrets
import psycopg2
from psycopg2 import OperationalError
import uvicorn
import uuid
import joblib
import asyncio
import xgboost as xgb
import numpy as np
from starlette.responses import JSONResponse

import matplotlib.pyplot as plt
import threading
import os

from collections import deque
from datetime import datetime, timedelta

performance_stats = []
active_devices = set()
inference_timestamps = deque()

GRAPH_OUTPUT_DIR = "/Users/rohan/Desktop/ScienceFair/device_graph"
os.makedirs(GRAPH_OUTPUT_DIR, exist_ok=True)


inference_count = 0
total_inference_time = 0.0
average_inference_time = 0.0

# ------------------------------------------------------------------------
# fastAPI application and template declaration
# ------------------------------------------------------------------------

app = FastAPI(title="broker testing_server")
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

# ------------------------------------------------------------------------
# loading the machine learning model int '//models' path
# ------------------------------------------------------------------------

model = joblib.load("/Users/rohan/Desktop/ScienceFair/models/xgb_model.joblib")

# ------------------------------------------------------------------------
# mapping the classification
# ------------------------------------------------------------------------

label_mapping = {
    'normal': 0,
    'dos_synflooding': 1,
    'mirai_ackflooding': 2,
    'host_discovery': 3,
    'telnet_bruteforce': 4,
    'mirai_httpflooding': 5,
    'mirai_udpflooding': 6,
    'mitm_arpspoofing': 7,
    'scanning_host': 8,
    'scanning_port': 9,
    'scanning_os': 10
}

# reverse mapping for classification
reverse_label_mapping = {value: key for key, value in label_mapping.items()}

# ------------------------------------------------------------------------
# Memory for the network storage
# ------------------------------------------------------------------------

networks_data: Dict[str, Dict[str, Any]] = {}

original_device_edges: Dict[str, Dict[str, list]] = {}

device_mitigation_status: Dict[str, Dict[str, Any]] = {}

# ------------------------------------------------------------------------
# Databases
# ------------------------------------------------------------------------

connection = None
try:
    connection = psycopg2.connect(
        database="cyberdome",
        host="localhost",
        port="5432"
    )
    print("Connection to PostgreSQL DB successful")
except OperationalError as e:
    print(f"The error '{e}' occurred")


# ------------------------------------------------------------------------
# Database queries
# ------------------------------------------------------------------------

def create_client(username, password):
    try:
        cursor = connection.cursor()
        query = """
        INSERT INTO client (username, password, network_id, network_name) VALUES(
            %s,
            %s,
            ARRAY[]::varchar(40)[],
            ARRAY[]::varchar(25)[]
        );
        """
        cursor.execute(query, (username, password))
        connection.commit()
    except OperationalError as e:
        print(f"Database error: {e}")
    return None


def check_admin_exists(admin, password):
    try:
        cursor = connection.cursor()
        query = "SELECT EXISTS(SELECT 1 FROM admin WHERE admin = %s)"
        cursor.execute(query, (admin,))
        result = cursor.fetchone()[0]
        if result:
            query = "SELECT password FROM admin WHERE admin = %s"
            cursor.execute(query, (admin,))
            return cursor.fetchone()[0] == password
        return result
    except OperationalError as e:
        print(f"Database error: {e}")
        return None


def client_exists(username):
    try:
        cursor = connection.cursor()
        query = "SELECT EXISTS(SELECT 1 FROM client WHERE username = %s)"
        cursor.execute(query, (username,))
        return cursor.fetchone()[0]
    except Exception as e:
        print(f"Database error: {e}")
        return None


def check_client_exists(username, password):
    try:
        result = client_exists(username)
        if result:
            cursor = connection.cursor()
            query = "SELECT password FROM client WHERE username = %s"
            cursor.execute(query, (username,))
            return cursor.fetchone()[0] == password
        return result
    except OperationalError as e:
        print(f"Database error: {e}")
        return None


# -------------------------------------------------------------------------------
# session token dictionaries
# -------------------------------------------------------------------------------

client_session: Dict[str, str] = {}
admin_session: Dict[str, str] = {}

# Initialize networks_data from DB
cur = connection.cursor()
cur.execute("SELECT * FROM client")
rows = cur.fetchall()
for row in rows:
    curr = row[3]  # network_id array
    for network_id in curr:
        networks_data[network_id] = {
            "packets_received": 0,
            "packets": deque(),
            "topology": {"nodes": [], "edges": []},
            "network_name": "",
            "device_status": {}
        }
        if network_id not in device_mitigation_status:
            device_mitigation_status[network_id] = {}


# ------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------

def require_login(request: Request) -> str:
    the_cook = request.cookies.get("session_id")
    if the_cook not in client_session:
        return RedirectResponse(url="/login", status_code=302)
    return client_session[the_cook]


def get_network(network_id: str) -> Dict[str, Any]:
    if network_id not in networks_data:
        networks_data[network_id] = {
            "packets_received": 0,
            "packets": deque(),
            "topology": {"nodes": [], "edges": []},
            "network_name": "",
            "device_status": {}
        }
    return networks_data[network_id]


# ------------------------------------------------------------------------
# Multi-step Mitigation Helpers
# ------------------------------------------------------------------------

def ensure_device_tracker_exists(network_id: str, device: str):
    if network_id not in device_mitigation_status:
        device_mitigation_status[network_id] = {}
    if device not in device_mitigation_status[network_id]:
        device_mitigation_status[network_id][device] = {
            "state": "none",
            "start_time": 0.0,
            "router_id": None
        }


def current_mitigation_state(network_id: str, device: str) -> str:
    ensure_device_tracker_exists(network_id, device)
    return device_mitigation_status[network_id][device]["state"]


def set_mitigation_state(network_id: str, device: str, state: str):
    ensure_device_tracker_exists(network_id, device)
    device_mitigation_status[network_id][device]["state"] = state
    device_mitigation_status[network_id][device]["start_time"] = time.time()


def set_router_id(network_id: str, device: str, router_id: str):
    device_mitigation_status[network_id][device]["router_id"] = router_id


def get_router_id(network_id: str, device: str) -> str:
    return device_mitigation_status[network_id][device].get("router_id")


def time_in_current_state(network_id: str, device: str) -> float:
    return time.time() - device_mitigation_status[network_id][device]["start_time"]


# ------------------------------------------------------------------------
# Utilities for proxy router and quarantine edges
# ------------------------------------------------------------------------

def get_main_router_node_id(topology):
    for node in topology["nodes"]:
        if "main" in node["id"]:
            return node["id"]
    return None


def ensure_proxy_router(topology, proxy_id: str = "proxy_router"):
    for node in topology["nodes"]:
        if node["id"] == proxy_id:
            return
    topology["nodes"].append({
        "id": proxy_id,
        "label": f"{proxy_id} (proxy)",
        "color": "#FF8C00"
    })


def remove_proxy_router(topology, proxy_id: str = "proxy_router"):
    topology["nodes"] = [n for n in topology["nodes"] if n["id"] != proxy_id]
    topology["edges"] = [
        e for e in topology["edges"] if e["from"] != proxy_id and e["to"] != proxy_id
    ]


def remove_edges_between(topology, node_a, node_b):
    topology["edges"] = [
        e for e in topology["edges"]
        if not ((e["from"] == node_a and e["to"] == node_b) or (e["from"] == node_b and e["to"] == node_a))
    ]


def add_edge(topology, node_a, node_b):
    for e in topology["edges"]:
        if (e["from"] == node_a and e["to"] == node_b) or (e["from"] == node_b and e["to"] == node_a):
            return
    topology["edges"].append({"from": node_a, "to": node_b})


def remove_other_edges_of_device(topology, device):
    topology["edges"] = [e for e in topology["edges"] if e["from"] != device and e["to"] != device]


def is_any_device_in_state(network_id, state):
    dev_states = device_mitigation_status.get(network_id, {})
    for _, st in dev_states.items():
        if st["state"] == state:
            return True
    return False


# ------------------------------------------------------------------------
# Backup and Restore Helpers for Segmentation
# ------------------------------------------------------------------------

def backup_device_edges(network_id: str, device: str, topology: Dict[str, Any]):
    if network_id not in original_device_edges:
        original_device_edges[network_id] = {}
    original_device_edges[network_id][device] = [
        edge for edge in topology.get("edges", [])
        if edge["from"] == device or edge["to"] == device
    ]


# ------------------------------------------------------------------------
# Mitigation Steps
# ------------------------------------------------------------------------

async def apply_flow_control(network_id: str, device: str):
    network = get_network(network_id)
    network["device_status"][device] = "flow_control"
    set_mitigation_state(network_id, device, "flow_control")
    print(f"[DEBUG] Flow control started for {device} in network {network_id}.")


async def apply_network_segmentation(network_id: str, device: str):
    network = get_network(network_id)
    topology = network["topology"]

    if not any(n["id"] == device for n in topology["nodes"]):
        topology["nodes"].append({"id": device, "label": device, "color": "#FF8C00"})

    backup_device_edges(network_id, device, topology)
    remove_other_edges_of_device(topology, device)
    ensure_proxy_router(topology)
    add_edge(topology, device, "proxy_router")

    network["device_status"][device] = "segmented"
    set_mitigation_state(network_id, device, "segmented")
    set_router_id(network_id, device, "proxy_router")
    print(f"[DEBUG] Device {device} in network {network_id} is now segmented exclusively via proxy_router.")


async def apply_quarantine(network_id: str, device: str, duration: int = 15):
    network = get_network(network_id)
    topology = network["topology"]

    remove_other_edges_of_device(topology, device)
    network["device_status"][device] = "quarantined"
    set_mitigation_state(network_id, device, "quarantined")
    print(f"[DEBUG] Device {device} quarantined for {duration} seconds in network {network_id} - all edges removed.")

    await asyncio.sleep(duration)
    if current_mitigation_state(network_id, device) == "quarantined":

        await restore_topology(network_id, device)


async def restore_topology(network_id: str, device: str):
    network = get_network(network_id)
    topology = network["topology"]
    print(f"[DEBUG] Restoring topology for device {device} in network {network_id}.")

    remove_edges_between(topology, device, "proxy_router")

    if network_id in original_device_edges and device in original_device_edges[network_id]:
        remove_other_edges_of_device(topology, device)
        for edge in original_device_edges[network_id][device]:
            add_edge(topology, edge["from"], edge["to"])
        del original_device_edges[network_id][device]
    else:
        main_router_id = get_main_router_node_id(topology)
        if main_router_id:
            add_edge(topology, device, main_router_id)

    network["device_status"][device] = "active"
    set_router_id(network_id, device, "")
    set_mitigation_state(network_id, device, "none")
    print(f"[DEBUG] Restoration complete for device {device} in network {network_id}.")

    if not is_any_device_in_state(network_id, "segmented"):
        remove_proxy_router(topology)
        print(f"[DEBUG] Proxy router removed from network {network_id} because no segmented devices remain.")


async def check_mitigation_status(network_id: str, device: str):
    state = current_mitigation_state(network_id, device)

    if state == "flow_control":
        if time_in_current_state(network_id, device) > 10:
            print(f"[DEBUG] Flow control expired for device {device} in network {network_id}.")
            await apply_network_segmentation(network_id, device)

    elif state == "segmented":
        if time_in_current_state(network_id, device) > 15:
            print(f"[DEBUG] Segmentation expired for device {device} in network {network_id}.")
            await restore_topology(network_id, device)


async def quarantine_device_immediate(network_id: str, device: str, timeout: int = 5):
    network = get_network(network_id)
    network["device_status"][device] = "quarantined"
    await asyncio.sleep(timeout)
    if network["device_status"].get(device) == "quarantined":
        network["device_status"][device] = "active"


# ------------------------------------------------------------------------
# Page exception handler endpoint
# ------------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def page_exception_handler(request: Request, exc: HTTPException):
    print(f"Page exception handler: {exc}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"status_code": "error", "message": exc.detail}
    )


# ------------------------------------------------------------------------
# Network End-points
# ------------------------------------------------------------------------

@app.get("/network/{network_id}/packets")
async def get_network_packets(network_id: str, user: str = Depends(require_login)):
    network = get_network(network_id)
    return network.get("packets", [])


@app.get("/network/{network_id}/topology")
async def get_network_topology(network_id: str, user: str = Depends(require_login)):
    network = get_network(network_id)
    topology = network["topology"]
    device_status = network.get("device_status", {})
    for node in topology.get("nodes", []):
        status = device_status.get(node["id"], "active")
        node["label"] = f"{node['id']} ({status})"
        if status == "active":
            node["color"] = "#40E0D0"
        elif status == "quarantined":
            node["color"] = "#DC143C"
        elif status == "flow_control":
            node["color"] = "#FFD700"
        elif status == "segmented":
            node["color"] = "#FF8C00"
        else:
            node["color"] = "#808080"
    return topology


@app.post("/update_topology")
async def update_topology(request: Request, user: str = Depends(require_login)):
    network_id = request.headers.get("X-Network-ID")
    if not network_id:
        raise HTTPException(status_code=400, detail="Missing X-Network-ID header")
    graph = await request.json()
    if "nodes" not in graph or "edges" not in graph:
        raise HTTPException(status_code=400, detail="Payload must contain 'nodes' and 'edges'")
    network = get_network(network_id)
    network["topology"] = graph
    return {"status": "success", "message": f"Topology updated for network {network_id}"}


@app.post("/register_network")
async def register_network(request: Request, user: str = Depends(require_login)):
    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading JSON data: {e}")
    network_name = payload.get("network_name")
    if not network_name:
        raise HTTPException(status_code=400, detail="Missing 'network_name' in payload")
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Missing 'user_id' in payload")
    cursor = connection.cursor()
    query = """
        UPDATE client
        SET network_name = array_append(network_name, %s)
        WHERE client_id=%s;
    """
    cursor.execute(query, (network_name, user_id))
    network_id = str(uuid.uuid4())
    query = """
        UPDATE client
        SET network_id = array_append(network_id, %s)
        WHERE client_id=%s;
    """
    cursor.execute(query, (network_id, user_id))
    connection.commit()
    networks_data[network_id] = {
        "packets_received": 0,
        "packets": deque(),
        "topology": {"nodes": [], "edges": []},
        "network_name": network_name,
        "device_status": {}
    }
    device_mitigation_status[network_id] = {}
    return {"status": "success", "network_id": network_id, "network_name": network_name, "user_id": user_id}

def performance_plotter():
    while True:
        if not performance_stats:
            time.sleep(5)
            continue
        x, y = zip(*performance_stats)
        plt.figure()
        plt.plot(x, y, label="Inferences/sec (5s window)", color='green')
        plt.xlabel("Number of Unique Devices")
        plt.ylabel("Inference Throughput (packets/sec)")
        plt.title("Server Throughput vs Devices")
        plt.legend()
        plt.tight_layout()
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        plt.savefig(os.path.join(GRAPH_OUTPUT_DIR, f"perf_{timestamp}.png"))
        plt.close()
        time.sleep(10)

threading.Thread(target=performance_plotter, daemon=True).start()


@app.post("/receive")
async def receive_packet(
        request: Request,
        background_tasks: BackgroundTasks,
        user: str = Depends(require_login)
):
    start_time = time.time()
    device = request.headers.get("X-Device", "Unknown")
    active_devices.add(device)

    network_id = request.headers.get("X-Network-ID")
    if not network_id:
        raise HTTPException(status_code=400, detail="Missing X-Network-ID header")
    device = request.headers.get("X-Device", "Unknown")
    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading JSON data: {e}")
    if "features" not in payload:
        raise HTTPException(status_code=400, detail="Missing 'features' in payload")
    features = payload["features"]
    try:
        features_array = np.array(features).reshape(1, -1)
        dmatrix = xgb.DMatrix(features_array)
        prediction = model.predict(dmatrix)
        numeric_class = prediction[0]
        classification = reverse_label_mapping.get(numeric_class, "Unknown")
    except Exception as e:
        classification = "Error"
    network = networks_data.get(
        network_id,
        {
            "packets_received": 0,
            "packets": deque(),
            "topology": {"nodes": [], "edges": []},
            "network_name": "",
            "device_status": {}
        }
    )
    network["packets_received"] += 1
    network["packets"].appendleft({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "device": device,
        "classification": classification
    })
    if len(network["packets"]) > 25:
        network["packets"].pop()
    ensure_device_tracker_exists(network_id, device)
    await check_mitigation_status(network_id, device)
    if classification == "normal":
        return {"status": "success", "message": f"Normal packet for device {device}."}
    if classification == "mirai_ackflooding":
        background_tasks.add_task(apply_quarantine, network_id, device, 15)
        return {"status": "success", "message": f"Mirai ACK flooding - quarantining device {device} for 15s."}
    current_state = current_mitigation_state(network_id, device)
    if current_state == "none":
        background_tasks.add_task(apply_flow_control, network_id, device)
    elif current_state == "flow_control":
        background_tasks.add_task(apply_network_segmentation, network_id, device)
    elif current_state == "segmented":
        background_tasks.add_task(apply_quarantine, network_id, device, 15)
    duration = time.time() - start_time
    now = datetime.now()
    inference_timestamps.append(now)

    # Remove entries older than 5 seconds
    cutoff = now - timedelta(seconds=5)
    while inference_timestamps and inference_timestamps[0] < cutoff:
        inference_timestamps.popleft()

    # Throughput in inferences per second
    inferences_per_sec = len(inference_timestamps) / 5.0
    active_devices.add(device)
    performance_stats.append((len(active_devices), inferences_per_sec))
    return {"status": "success", "message": f"Classification={classification} mitigation in progress."}


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    the_cook = request.cookies.get("session_id")
    if the_cook in client_session:
        return RedirectResponse(url="/client_dashboard", status_code=302)
    return templates.TemplateResponse("home_page.html", {"request": request})


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    the_cook = request.cookies.get("session_id")
    if the_cook in client_session:
        return RedirectResponse(url="/client_dashboard", status_code=302)
    return templates.TemplateResponse("client_login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    if check_client_exists(username, password):
        session_id = secrets.token_hex(16)
        client_session[session_id] = username
        response = RedirectResponse(url="/client_dashboard", status_code=302)
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return response
    else:
        return templates.TemplateResponse("client_login.html",
                                          {"request": request, "error": "Invalid username or password"})


@app.get("/signup", response_class=HTMLResponse)
async def signup_get(request: Request):
    return templates.TemplateResponse("client_signup.html", {"request": request})


@app.post("/signup", response_class=HTMLResponse)
async def signup_post(request: Request, username: str = Form(...), password: str = Form(...),
                      confirm_password: str = Form(...)):
    if client_exists(username):
        return templates.TemplateResponse("client_signup.html",
                                          {"request": request, "error": "Username already exists"})
    else:
        if password != confirm_password:
            return templates.TemplateResponse("client_signup.html",
                                              {"request": request, "error": "Passwords do not match"})
        create_client(username, password)
        session_id = secrets.token_hex(16)
        client_session[session_id] = username
        response = RedirectResponse(url="/client_dashboard", status_code=302)
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return response


@app.get("/logout")
async def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in client_session:
        del client_session[session_id]
    if session_id in admin_session:
        del admin_session[session_id]
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("session_id")
    return response


@app.get("/client_dashboard", response_class=HTMLResponse)
async def client_dashboard(request: Request):
    the_cook = request.cookies.get("session_id")
    if the_cook not in client_session:
        return RedirectResponse(url="/client_login", status_code=302)
    return templates.TemplateResponse("client_dashboard.html",
                                      {"request": request, "user_name": client_session[the_cook]})


@app.get("/user/network/{network_id}/packets")
async def get_network_packets(network_id: str, user: str = Depends(require_login)):
    network = get_network(network_id)
    return network["packets"]


@app.get("/{user_name}/networks")
async def user_networks_get(request: Request, user_name: str):
    res = []
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM client WHERE username = %s", (user_name,))
    rep = cursor.fetchall()[0]
    for idx in range(len(rep[3])):
        net_id = rep[3][idx]
        net_name = rep[4][idx]
        res.append({
            "network_id": net_id,
            "network_name": net_name,
            "packets_count": networks_data[net_id].get("packets_received", 0),
            "topology_updated": bool(networks_data[net_id].get("topology", {}).get("nodes", []))
        })
    return res


@app.get("/user/{user_name}/network/{network_id}")
async def network_details_get(request: Request, user_name: str, network_id: str):
    the_cook = request.cookies.get("session_id")
    if the_cook not in client_session:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("network_details.html", {"request": request, "network_id": network_id})


@app.get("/admin_login", response_class=HTMLResponse)
async def admin_login_get(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})


@app.post("/admin_login", response_class=HTMLResponse)
async def admin_login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    if check_admin_exists(username, password):
        session_id = secrets.token_hex(16)
        admin_session[session_id] = username
        response = RedirectResponse(url="/admin_dashboard", status_code=302)
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return response
    else:
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": "Invalid username or password"}
        )


@app.get("/admin_dashboard", response_class=HTMLResponse)
async def admin_dashboard_get(request: Request):
    the_cook = request.cookies.get("session_id")
    if the_cook not in admin_session:
        return RedirectResponse(url="/admin_login", status_code=302)
    return templates.TemplateResponse("admin_dashboard.html", {"request": request})


@app.get("/users")
async def users_get(request: Request):
    res = []
    cursor = connection.cursor()
    cursor.execute("SELECT username, network_id FROM client")
    rows = cursor.fetchall()
    for row in rows:
        res.append({
            "user_name": row[0],
            "networks_count": len(row[1])
        })
    return res


@app.get("/user/{user_name}")
async def user_get(request: Request, user_name: str):
    the_cook = request.cookies.get("session_id")
    if the_cook not in admin_session:
        return RedirectResponse(url="/admin_login", status_code=302)
    return templates.TemplateResponse(
        "user_networks.html",
        {
            "request": request,
            "user_name": user_name
        }
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
