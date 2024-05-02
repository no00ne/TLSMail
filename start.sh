#!/bin/bash

# 启动SMTP服务器
python SMTPServer.py &

# 启动Flask应用
python app.py &

# 等待所有后台进程完成
wait