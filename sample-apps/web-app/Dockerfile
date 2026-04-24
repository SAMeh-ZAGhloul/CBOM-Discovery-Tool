FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create certificates directory
RUN mkdir -p /app/certs

# Generate self-signed certificate for TLS demo
RUN openssl req -x509 -newkey rsa:2048 -keyout /app/certs/key.pem -out /app/certs/cert.pem     -days 365 -nodes -subj "/CN=sample-web-app/O=CBOM Demo/C=US"     && chmod 600 /app/certs/key.pem

COPY app.py .

EXPOSE 8443

CMD ["python", "app.py"]
