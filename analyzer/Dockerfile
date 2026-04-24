FROM python:3.11-slim

WORKDIR /app

# Install OS dependencies for traffic generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sshpass \
    openssh-client \
    postgresql-client \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create directories for logs and output
RUN mkdir -p /app/logs /app/cbom

EXPOSE 5000

CMD ["python", "app.py"]
