FROM python:3.11-slim

WORKDIR /app

COPY XApp_Normal.py .
COPY XApp_Malicious.py .

# 透過環境變數決定啟動哪個腳本
# docker-compose.yml 裡設定 MODE=Normal 或 MODE=Malicious
ENV MODE=normal

CMD ["sh", "-c", "python -u XApp_${MODE}.py"]