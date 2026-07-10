FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5001 5002 5003

CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--worker-class", "eventlet", "--workers", "1", "boltmart.app:create_app()"]
