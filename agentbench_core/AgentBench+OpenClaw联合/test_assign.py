import requests
import time
import json

base = "http://localhost:5000/api"
agent = "gpt-3.5-turbo-0613"
task = "dbbench-std"

# 1. 获取任务索引列表
print(f"Fetching indices for task: {task}")
resp = requests.get(f"{base}/get_indices", params={"name": task})
if resp.status_code != 200:
    print(f"Failed to get indices: {resp.text}")
    exit(1)

indices = resp.json()
if not indices:
    print("No indices found. Worker may have no samples.")
    exit(1)

print(f"Found {len(indices)} indices. Using first one: {indices[0]}")
index = indices[0]

# 2. 分配任务
print(f"Assigning task {task} index {index} to agent {agent}...")
assign_resp = requests.post(f"{base}/assign", json={
    "agent": agent,
    "task": task,
    "index": index
})

if assign_resp.status_code != 200:
    print(f"Assignment failed: {assign_resp.text}")
    exit(1)

session_id = assign_resp.json().get("session_id")
if not session_id:
    print("No session_id returned.")
    exit(1)

print(f"Task assigned. Session ID: {session_id}")

# 3. 轮询结果（最多等待 120 秒）
print("Waiting for task to complete...")
for _ in range(60):
    result_resp = requests.get(f"{base}/get_result", params={"session_id": session_id})
    if result_resp.status_code != 200:
        print(f"Error getting result: {result_resp.text}")
        time.sleep(2)
        continue

    data = result_resp.json()
    if data.get("finished"):
        print("\n✅ Task completed!")
        # 美化输出结果
        print(json.dumps(data, indent=2, ensure_ascii=False))
        break
    else:
        print(".", end="", flush=True)
    time.sleep(2)
else:
    print("\n⚠️ Timeout waiting for result. The task may still be running.")
