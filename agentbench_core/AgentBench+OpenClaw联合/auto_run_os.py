import yaml
import json
import requests
import time
import subprocess
import re
import threading
from queue import Queue
from src.client.agents import HTTPAgent

# ---------------------- 配置 ----------------------
CONTROLLER_URL = "http://localhost:5000/api"
TASK_NAME = "os-std"
AGENT_NAME = "gpt-3.5-turbo-0613"
NUM_SAMPLES = 144
OUTPUT_FILE = "os_std_results.jsonl"

# ---------------------- 加载 Agent ----------------------
with open("configs/agents/openai-chat.yaml") as f:
    agent_config = yaml.safe_load(f)
agent = HTTPAgent(**agent_config["parameters"])

# ---------------------- 日志监控器 ----------------------
session_queue = Queue()

def monitor_controller_logs():
    process = subprocess.Popen(
        ["docker", "logs", "-f", "agentrl-controller"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    pattern = re.compile(r"Created session (\d+) for task os-std, index (\d+)")
    for line in process.stdout:
        match = pattern.search(line)
        if match:
            session_id = int(match.group(1))
            index = int(match.group(2))
            session_queue.put((session_id, index))

monitor_thread = threading.Thread(target=monitor_controller_logs, daemon=True)
monitor_thread.start()

# ---------------------- 执行样本 ----------------------
def run_sample_via_controller(index):
    # 1. 启动样本
    resp = requests.post(
        f"{CONTROLLER_URL}/start_sample",
        json={"name": TASK_NAME, "index": index}
    )
    if resp.status_code != 200:
        return {"index": index, "error": "start_sample_failed", "details": resp.text}

    # 2. 等待捕获 session_id
    session_id = None
    timeout = time.time() + 30
    while time.time() < timeout:
        try:
            sid, idx = session_queue.get(timeout=1)
            if idx == index:
                session_id = sid
                break
            else:
                session_queue.put((sid, idx))
        except:
            pass
    if session_id is None:
        return {"index": index, "error": "session_id_timeout"}

    print(f"  -> Session {session_id} started, fetching initial context...")

    # 3. 发送空交互，获取任务初始描述
    interact_resp = requests.post(
        f"{CONTROLLER_URL}/interact",
        json={"session_id": session_id, "agent_response": {"content": ""}}
    )
    if interact_resp.status_code != 200:
        return {"index": index, "error": "initial_interact_failed", "details": interact_resp.text}

    data = interact_resp.json()
    output = data.get("output")
    if not output:
        return {"index": index, "error": "no_output", "data": data}

    round_count = 0
    while round_count < 50:
        status = output.get("status")
        if status != "RUNNING":
            return {"index": index, "status": status, "output": output}

        history = output.get("history", [])
        
        # Agent 推理
        try:
            agent_resp = agent.inference(history)
            content = agent_resp.content
        except Exception as e:
            requests.post(f"{CONTROLLER_URL}/cancel", json={"session_id": session_id})
            return {"index": index, "error": "agent_inference_failed", "details": str(e)}

        # 发送交互
        interact_resp = requests.post(
            f"{CONTROLLER_URL}/interact",
            json={"session_id": session_id, "agent_response": {"content": content}}
        )
        if interact_resp.status_code != 200:
            return {"index": index, "error": "interact_failed", "details": interact_resp.text}

        data = interact_resp.json()
        output = data.get("output")
        if not output:
            return {"index": index, "error": "no_output", "data": data}
        round_count += 1

    requests.post(f"{CONTROLLER_URL}/cancel", json={"session_id": session_id})
    return {"index": index, "error": "max_rounds_exceeded"}

# ---------------------- 批量执行 ----------------------
print(f"Starting batch execution of {NUM_SAMPLES} samples for task '{TASK_NAME}'")
print(f"Results will be saved to {OUTPUT_FILE}\n")

with open(OUTPUT_FILE, "a") as out_f:
    for idx in range(NUM_SAMPLES):
        print(f"--- Processing index {idx} ---")
        result = run_sample_via_controller(idx)
        out_f.write(json.dumps(result, ensure_ascii=False) + "\n")
        out_f.flush()
        status = result.get('status', result.get('error', 'unknown'))
        print(f"  -> Result: {status}\n")
        time.sleep(2)

print(f"\nAll tasks finished. Results saved to {OUTPUT_FILE}")
