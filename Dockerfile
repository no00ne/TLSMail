# 使用官方的Python基础镜像
FROM python:3.11-buster

# 设置工作目录
WORKDIR /app

# 将当前目录的内容复制到工作目录中
COPY . /app

# 更新源，安装依赖，清理缓存，并转换 start.sh 脚本的换行符
RUN echo "deb http://mirrors.aliyun.com/debian/ buster main non-free contrib\n\
deb-src http://mirrors.aliyun.com/debian/ buster main non-free contrib\n\
deb http://mirrors.aliyun.com/debian-security buster/updates main\n\
deb-src http://mirrors.aliyun.com/debian-security buster/updates main\n\
deb http://mirrors.aliyun.com/debian/ buster-updates main non-free contrib\n\
deb-src http://mirrors.aliyun.com/debian/ buster-updates main non-free contrib" > /etc/apt/sources.list && \
    apt-get update && apt-get install -y gcc libpq-dev python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's/\r$//' start.sh

# 更新pip并安装依赖
RUN pip install --upgrade pip && \
    pip install -i https://mirrors.aliyun.com/pypi/simple/ --no-cache-dir -r requirements.txt

# 暴露端口，使得SMTP服务可以被访问
EXPOSE 5000

# 运行app.py当Docker启动时
CMD ["bash", "start.sh"]

