START_PID=$(ps aux | grep 'start.sh' | awk '{print $2}' | grep -v grep)

# 获取 SMTPServer.py 进程的 PID
SMTP_PID=$(ps aux | grep '[p]ython3 SMTPServer.py' | awk '{print $2}')

# 获取 app.py 进程的 PID
APP_PID=$(ps aux | grep '[p]ython3 app.py' | awk '{print $2}')

# 杀死两个 Python 进程
kill $SMTP_PID $APP_PID $START_PID
