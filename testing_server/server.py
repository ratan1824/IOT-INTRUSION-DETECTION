from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from datetime import datetime
from typing import Dict, Any, Optional
import uuid
import joblib
import uvicorn
import logging
import asyncio
import xgboost as xgb
import numpy as np  # needed for inference
import secrets  # used to generate secure session tokens

# ------------------------------------------------------------------------
# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------
# FastAPI app and template setup
app = FastAPI(title="Multi-Network Packet Monitor")
templates = Jinja2Templates(directory="templates")

# ------------------------------------------------------------------------
# Load the ML model (adjust path as needed)
model = joblib.load("/Users/rohan/Desktop/ScienceFair/models/xgb_model.joblib")

# Label mappings
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
reverse_label_mapping = {v: k for k, v in label_mapping.items()}

# ------------------------------------------------------------------------
# Global in-memory store
# ------------------------------------------------------------------------
# Each network ID maps to a dict with packets, topology, network name, and device statuses.
networks_data: Dict[str, Dict[str, Any]] = {}

# Simple in-memory user database (username -> password).
# In a real-world scenario, store hashed passwords in a secure DB.
USER_DB = {
    "admin": "password123"
}

# Session token -> username
# In production, store sessions in a more persistent way or use a library (e.g., fastapi-login).
SESSIONS: Dict[str, str] = {}


# ------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------
def get_network(network_id: str) -> Dict[str, Any]:
    if network_id not in networks_data:
        networks_data[network_id] = {
            "packets": [],
            "topology": {"nodes": [], "edges": []},
            "network_name": "",
            "device_status": {}
        }
    return networks_data[network_id]


def get_current_user(request: Request) -> Optional[str]:
    """
    Reads the 'session_id' cookie. Returns the corresponding username if valid.
    Otherwise returns None.
    """
    session_id = request.cookies.get("session_id")
    if session_id and session_id in SESSIONS:
        return SESSIONS[session_id]
    return None


def require_login(request: Request) -> str:
    """
    Dependency that checks if a user is logged in.
    If not, redirects to /login.
    """
    user = get_current_user(request)
    if not user:
        # Redirect unauthenticated users to the login page
        return RedirectResponse(url="/login", status_code=302)
    return user


# ------------------------------------------------------------------------
# Authentication Endpoints
# ------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    """
    Serves the login form (GET).
    """
    return templates.TemplateResponse("client_login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
async def login_post(
        request: Request,
        username: str = Form(...),
        password: str = Form(...)
):
    """
    Handles the login form submission (POST).
    """
    # Validate credentials
    if username in USER_DB and USER_DB[username] == password:
        # Credentials valid, create a session
        session_id = secrets.token_hex(16)
        SESSIONS[session_id] = username
        # Send session_id cookie to client
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return response
    else:
        # Invalid credentials; show an error on the login page
        return templates.TemplateResponse("client_login.html", {
            "request": request,
            "error": "Invalid username or password"
        })


@app.get("/logout")
async def logout(request: Request):
    """
    Clears the session cookie and removes the session from SESSIONS.
    """
    session_id = request.cookies.get("session_id")
    if session_id in SESSIONS:
        del SESSIONS[session_id]
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session_id")
    return response


# ------------------------------------------------------------------------
# Existing Endpoints (With Authentication)
# ------------------------------------------------------------------------
@app.post("/register_network")
async def register_network(request: Request, user: str = Depends(require_login)):
    """
    Register a new network by providing a network name.
    The testing_server assigns a unique network ID and returns it.
    """
    # If user is uninitialized, require_login returns RedirectResponse,
    # so this code won't run if not logged in.

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading JSON data: {e}")
    network_name = payload.get("network_name")
    if not network_name:
        raise HTTPException(status_code=400, detail="Missing 'network_name' in payload")
    network_id = str(uuid.uuid4())
    networks_data[network_id] = {
        "packets": [],
        "topology": {"nodes": [], "edges": []},
        "network_name": network_name,
        "device_status": {}
    }
    logger.info(f"Registered network '{network_name}' with ID {network_id}")
    return {"status": "success", "network_id": network_id, "network_name": network_name}


async def quarantine_device(network_id: str, device: str, timeout: int = 5):
    """
    Quarantine a device by setting its status to 'quarantined'.
    After 'timeout' seconds, the device is released (status set to 'active').
    """
    network = get_network(network_id)
    network["device_status"][device] = "quarantined"
    logger.info(f"Device {device} in network {network_id} quarantined for {timeout} seconds.")
    await asyncio.sleep(timeout)
    network["device_status"][device] = "active"
    logger.info(f"Device {device} in network {network_id} released from quarantine.")


@app.post("/receive")
async def receive_packet(
        request: Request,
        background_tasks: BackgroundTasks,
        user: str = Depends(require_login)
):
    """
    Expects headers: X-Network-ID and X-Device.
    Reads the JSON payload containing processed features, runs inference,
    and stores the classification result. If device is suspicious,
    schedules a quarantine task.

    This route is protected so only logged-in users can send data.
    """
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
        logger.error(f"Inference error: {e}")
        classification = "Error"

    packet_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "device": device,
        "classification": classification
    }
    network = get_network(network_id)
    network["packets"].append(packet_entry)
    logger.info(f"Stored packet: {packet_entry}")

    if classification != "normal":
        # Schedule quarantine for this device.
        background_tasks.add_task(quarantine_device, network_id, device, 5)

    return {"status": "success", "message": f"Classification result received for network {network_id}"}


@app.post("/update_topology")
async def update_topology(request: Request, user: str = Depends(require_login)):
    """
    Expects header: X-Network-ID; payload must contain 'nodes' and 'edges'.
    Updates the network topology for the given network.
    """
    network_id = request.headers.get("X-Network-ID")
    if not network_id:
        raise HTTPException(status_code=400, detail="Missing X-Network-ID header")
    graph = await request.json()
    if "nodes" not in graph or "edges" not in graph:
        raise HTTPException(status_code=400, detail="Payload must contain 'nodes' and 'edges'")

    network = get_network(network_id)
    network["topology"] = graph
    logger.info(f"Topology updated for network {network_id}: {graph}")
    return {"status": "success", "message": f"Topology updated for network {network_id}"}


@app.get("/networks")
async def list_networks(user: str = Depends(require_login)):
    result = []
    for net_id, data in networks_data.items():
        result.append({
            "network_id": net_id,
            "network_name": data.get("network_name", ""),
            "packets_count": len(data.get("packets", [])),
            "topology_updated": bool(data.get("topology", {}).get("nodes"))
        })
    return result


@app.get("/network/{network_id}/packets")
async def get_network_packets(network_id: str, user: str = Depends(require_login)):
    network = get_network(network_id)
    return network["packets"]


@app.get("/network/{network_id}/topology")
async def get_network_topology(network_id: str, user: str = Depends(require_login)):
    network = get_network(network_id)
    topology = network["topology"]
    device_status = network.get("device_status", {})
    # Update node labels and colors based on device status
    for node in topology.get("nodes", []):
        status = device_status.get(node["id"], "active")
        node["label"] = f"{node['id']} ({status})"
        # Use turquoise for active devices, crimson for quarantined
        node["color"] = "#40E0D0" if status == "active" else "#DC143C"
    return topology


@app.get("/", response_class=HTMLResponse)
async def main_dashboard(request: Request):
    """
    Shows the main dashboard – if user is not logged in, redirect to /login.
    """
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    # Render the main dashboard for the logged-in user
    return templates.TemplateResponse("main_dashboard.html", {
        "request": request,
        "username": user  # pass the username if you want to display it
    })


@app.get("/network/{network_id}", response_class=HTMLResponse)
async def network_dashboard(request: Request, network_id: str):
    """
    Shows a network's dashboard – if user is not logged in, redirect to /login.
    """
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    network = get_network(network_id)
    return templates.TemplateResponse("network_dashboard.html", {
        "request": request,
        "network_id": network_id,
        "network_name": network.get("network_name", "Unnamed Network"),
        "username": user
    })


# ------------------------------------------------------------------------
# Run the app
# ------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)