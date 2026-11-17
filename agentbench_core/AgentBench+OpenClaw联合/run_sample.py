import yaml
import json
import requests
import time
from src.client.agents import HTTPAgent

# ---------- 配置 ----------
worker_ip = "172.18.0.3"          # 通过 docker inspect 获得的 IP
worker_port = "5021"
worker_url = f"http://{worker_ip}:{worker_port}/api"
task_name = "os-std"
index = 0

# ---------- 创建 Agent ----------
with open("configs/agents/openai-chat.yaml") as f:
    agent_config = yaml.safe_load(f)
agent = HTTPAgent(**agent_config["parameters"])
print(f"Agent created: {agent.__class__.__name__}")

# ---------- 启动样本 ----------
start_payload = {"name": task_name, "index": index}
print(f"POST {worker_url}/start_sample")
print(f"Payload: {json.dumps(start_payload)}")

resp = requests.post(f"{worker_url}/start_sample", json=start_payload)
print(f"Response status: {resp.status_code}")
print(f"Response body (truncated): {resp.text[:300]}")

if resp.status_code != 200:
    print("Failed to start sample, exiting.")
    exit(1)

data = resp.json()
session_id = data.get("session_id")
if not session_id:
    print("Error: 'session_id' not found in response.")
    print("Full response:", json.dumps(data, indent=2))
    exit(1)

print(f"Session ID: {session_id}")

# ---------- 交互循环 ----------
print("Starting interaction loop...")
while True:
    output = data.get("output")
    if output is None:
        print("Error: No 'output' field in response.")
        break

    status = output.get("status")
    print(f"Current status: {status}")

    if status != "RUNNING":
        print("\n=== FINAL RESULT ===")
        print(json.dumps(data, indent=2, ensure_ascii=False))
        break

    # 获取对话历史
    history = output.get("history")
    try:
        agent_response = agent.inference(history)
        content = agent_response.content
    except Exception as e:
        print(f"Agent inference error: {e}")
        requests.post(f"{worker_url}/cancel", json={"session_id": session_id})
        break

    # 发送交互请求
    interact_payload = {
        "session_id": session_id,
        "agent_response": {"content": content}
    }
    interact_resp = requests.post(f"{worker_url}/interact", json=interact_payload)
    if interact_resp.status_code != 200:
        print(f"Interact failed: {interact_resp.text}")
        requests.post(f"{worker_url}/cancel", json={"session_id": session_id})
        break

    data = interact_resp.json()
    time.sleep(1)
