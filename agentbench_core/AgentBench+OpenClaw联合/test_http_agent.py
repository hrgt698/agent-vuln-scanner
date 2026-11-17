from src.client.agents.http_agent import HTTPAgent

# 填入你的脆弱靶机接口地址
agent = HTTPAgent(
    url="http://127.0.0.1:18789/api/v1/config",
    return_format="{response}"
)

# 空会话发起探测
test_history = []
result = agent.inference(test_history)
print("框架调用靶机返回结果：")
print(result)
