@echo off
chcp 65001 >nul
color 0A
echo ===================================================
echo      评估平台 - 目标靶机一键启动
echo ===================================================
echo.

echo [*] 1. 正在进行安全配置检查...
if not exist ".env" (
    color 0E
    echo [-] 警告：找不到 .env 配置文件！
    echo [*] 系统已为你自动生成了基础模板...
    copy .env.example .env >nul
    echo.
    echo [-] 【安全阻断】请不要裸奔！
    echo [-] 请打开当前目录下的 .env 文件，填入你自己的 API Token。
    echo [-] 填好并保存后，重新运行本脚本即可启动！
    pause
    exit /b
)

echo [+] 配置文件检查通过！
echo.

echo [*] 2. 正在检查 Docker 引擎是否运行...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [-] 致命错误：找不到 Docker 引擎！请先启动 Docker Desktop。
    pause
    exit /b
)

echo [*] 3. 正在启动脆弱靶机...
docker-compose up -d --build

echo.
echo ===================================================
echo [SUCCESS] 靶机已成功加载你的 Token 并运行在后台！
echo [INFO] 测试接口地址: http://127.0.0.1:18789/api/v1/config
echo ===================================================
pause