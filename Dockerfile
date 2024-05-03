# 使用官方的Python基础镜像
FROM python:3.11-slim-buster

# 设置工作目录
WORKDIR /app

# 将当前目录的内容复制到工作目录中
COPY . /app

RUN echo "deb http://mirrors.aliyun.com/debian/ buster main non-free contrib\n\
deb-src http://mirrors.aliyun.com/debian/ buster main non-free contrib\n\
deb http://mirrors.aliyun.com/debian-security buster/updates main\n\
deb-src http://mirrors.aliyun.com/debian-security buster/updates main\n\
deb http://mirrors.aliyun.com/debian/ buster-updates main non-free contrib\n\
deb-src http://mirrors.aliyun.com/debian/ buster-updates main non-free contrib" > /etc/apt/sources.list
# 安装项目依赖
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    python3-venv

# 创建虚拟环境
RUN python3 -m venv venv

# 激活虚拟环境
RUN . venv/bin/activate

# 更新pip到最新版本
RUN pip install --upgrade pip

# 使用阿里云的pip源来安装Python依赖
RUN pip install -i https://mirrors.aliyun.com/pypi/simple/ --no-cache-dir -r requirements.txt


# 暴露端口，使得SMTP服务可以被访问
EXPOSE 5000

# 运行app.py当Docker启动时
CMD ["bash", "start.sh"]