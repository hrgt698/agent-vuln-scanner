@echo off
chcp 65001 >nul
title 安全评估平台 - 一键启动

echo ========================================
echo     安全评估平台 一键启动
echo ========================================
echo.

set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"

echo [1/3] 启动靶机服务 (端口: 18789)...
echo 使用 docker-compose 启动靶机（与部署文档保持一致）...
cd /d "%ROOT_DIR%deploy"
docker-compose up -d --build
if %errorlevel% neq 0 (
    echo [警告] docker-compose 启动失败，尝试使用 Python 直接启动...
    start "target" cmd /k "cd /d "%ROOT_DIR%deploy" && python target_api.py"
)
cd /d "%ROOT_DIR%"

timeout /t 3 /nobreak >nul

echo [2/3] 启动后端服务 (端口: 8000)...
start "backend" cmd /k "cd /d "%ROOT_DIR%backend" && python main.py"

timeout /t 2 /nobreak >nul

echo [3/3] 启动前端服务 (端口: 5173)...
start "frontend" cmd /k "cd /d "%ROOT_DIR%frontend" && npm run dev"

echo.
echo ========================================
echo     所有服务正在启动中...
echo ========================================
echo.
echo 靶机地址: http://127.0.0.1:18789
echo 后端地址: http://127.0.0.1:8000
echo 前端地址: http://localhost:5173
echo.
echo 等待 5 秒后自动打开浏览器...
timeout /t 5 /nobreak >nul

start http://localhost:5173

echo.
echo 正在打开浏览器...
echo 注意: 请保持命令行窗口运行，不要关闭！
echo.
pause