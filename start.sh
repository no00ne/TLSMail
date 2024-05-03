#!/bin/bash

# 启动SMTP服务器
mkdir -p ./.log
touch ./.log/smtp_server.log
touch ./.log/flask_app.log

# 启动Flask应用并获取 PID
python3 app.py > ./.log/flask_app.log 2>&1 &
FLASK_APP_PID=$!

# 启动SMTP服务器并获取 PID
python3 SMTPServer.py > ./.log/smtp_server.log 2>&1 &
SMTP_SERVER_PID=$!

# 等待所有后台进程完成
wait $SMTP_SERVER_PID $FLASK_APP_PID

# 杀死SMTP服务器进程
kill $SMTP_SERVER_PID

# 杀死Flask应用进程
kill $FLASK_APP_PID
