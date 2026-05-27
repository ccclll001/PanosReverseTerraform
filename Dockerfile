FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY web_app.py .
COPY templates/ templates/

EXPOSE 8080

# Production: gunicorn (replace Flask dev server)
CMD ["gunicorn", "web_app:app", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "60"]
