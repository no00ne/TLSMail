#!/bin/bash

# 启动SMTP服务器
mkdir -p /.log
touch /.log/smtp_server.log
touch /.log/flask_app.log

python SMTPServer.py > /.log/smtp_server.log &

# 启动Flask应用
python app.py > /.log/flask_app.log &

# 等待所有后台进程完成
wait