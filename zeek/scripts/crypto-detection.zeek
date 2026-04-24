# crypto-detection.zeek
# Minimal cryptographic asset detection for CBOM generation

@load base/protocols/ssl
@load base/protocols/ssh
@load base/files/hash
@load base/files/x509

# Ensure x509 certificates are logged
@load protocols/ssl/known-certs

# Basic monitoring without complex logging structures
# Zeek will automatically log SSL and SSH connections with the default policies
