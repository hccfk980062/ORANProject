FROM python:3.11-slim

WORKDIR /app

# RIC 節點很單純，只需要基本網路功能
COPY RICNode.py .

EXPOSE 36421

CMD ["python", "-u", "RICNode.py"]