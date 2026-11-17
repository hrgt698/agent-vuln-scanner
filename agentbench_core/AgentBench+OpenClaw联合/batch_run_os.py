import yaml
import json
from tqdm import tqdm
from src.client.task import TaskClient
from src.client.agents import HTTPAgent

# 1. 加载Agent
with open("configs/agents/openai-chat.yaml") as f:
    agent_config = yaml.safe_load(f)
agent = HTTPAgent(**agent_config["parameters"])
print(f"Agent loaded: {agent.__class__.__name__}")

# 2. 创建TaskClient
task_name = "os-std"
controller_url = "http://localhost:5000/api"
client = TaskClient(name=task_name, controller_address=controller_url)

# 3. 获取所有样本索引
indices = client.get_indices()
print(f"Total samples: {len(indices)}")

# 4. 批量执行并保存结果
results = []
output_file = "os_star_results.jsonl"

# 使用tqdm显示进度
for idx in tqdm(indices, desc="Executing samples"):
    try:
        result = client.run_sample(idx, agent)
        # 将结果转换为可序列化的字典
        result_dict = result.dict() if hasattr(result, 'dict') else {"output": str(result)}
        result_dict["index"] = idx
        results.append(result_dict)
    except Exception as e:
        print(f"Sample {idx} failed: {e}")
        results.append({"index": idx, "error": str(e)})
    
    # 每完成一个就追加写入文件，防止意外中断丢失数据
    with open(output_file, "a") as f:
        f.write(json.dumps(results[-1], ensure_ascii=False) + "\n")

print(f"\nAll tasks finished. Results saved to {output_file}")
