FROM python:3.11-slim

WORKDIR /app

# 先複製 requirements 利用 Docker 快取層
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 建立 log 資料夾
RUN mkdir -p /app/logs

EXPOSE 36422

CMD ["python", "-u", "FSM_Interceptor.py"]