FROM ubuntu:22.04

# Install OpenSSH server
RUN apt-get update && apt-get install -y     openssh-server     && rm -rf /var/lib/apt/lists/*

# Create SSH host keys (RSA, ECDSA, ED25519)
RUN mkdir -p /var/run/sshd /root/.ssh && rm -f /etc/ssh/ssh_host_*_key* && ssh-keygen -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key -N "" && ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N "" && ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" && chmod 600 /etc/ssh/ssh_host_*_key

# Create demo user
RUN useradd -m -s /bin/bash cbomuser     && echo 'cbomuser:cbom_demo_2024!' | chpasswd

# Copy SSH config
COPY sshd_config /etc/ssh/sshd_config

# Expose SSH port
EXPOSE 22

# Start SSH daemon
CMD ["/usr/sbin/sshd", "-D", "-e"]
