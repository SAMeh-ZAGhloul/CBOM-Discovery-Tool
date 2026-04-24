FROM postgres:16

# Install openssl for certificate generation
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Create certificates directory
RUN mkdir -p /etc/postgresql/certs && chown postgres:postgres /etc/postgresql/certs && chmod 700 /etc/postgresql/certs

# Generate server certificates
RUN openssl req -new -x509 -days 365 -nodes -text     -out /etc/postgresql/certs/server.crt     -keyout /etc/postgresql/certs/server.key     -subj "/CN=postgres-db/O=CBOM Demo/C=US"     && chmod 644 /etc/postgresql/certs/server.crt     && chmod 600 /etc/postgresql/certs/server.key     && chown postgres:postgres /etc/postgresql/certs/*

# Generate CA certificate
RUN openssl req -new -x509 -days 365 -nodes -text     -out /etc/postgresql/certs/ca.crt     -keyout /etc/postgresql/certs/ca.key     -subj "/CN=CBOM Demo CA/O=CBOM Demo/C=US"     && chmod 644 /etc/postgresql/certs/ca.crt     && chmod 600 /etc/postgresql/certs/ca.key     && chown postgres:postgres /etc/postgresql/certs/*

# Copy custom PostgreSQL config
COPY postgresql.conf /etc/postgresql/postgresql.conf
COPY pg_hba.conf /etc/postgresql/pg_hba.conf
COPY init.sql /docker-entrypoint-initdb.d/init.sql

# Set PostgreSQL to use custom config
ENV POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256"

EXPOSE 5432 6432

CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"]
