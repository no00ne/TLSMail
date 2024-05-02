# 使用官方的Python基础镜像
FROM python:3.11-slim-buster

# 设置工作目录
WORKDIR /app

# 将当前目录的内容复制到工作目录中
COPY . /app

# 安装项目依赖
RUN pip install --no-cache-dir -r requirements.txt

# 暴露端口，使得SMTP服务可以被访问
EXPOSE 5000

# 运行app.py当Docker启动时
CMD ["bash", "start.sh"]