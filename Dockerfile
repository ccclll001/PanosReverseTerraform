FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY web_app.py .
COPY templates/ templates/

EXPOSE 8080

CMD ["python", "web_app.py"]
