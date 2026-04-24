# crypto-detection.zeek
# Minimal cryptographic asset detection for CBOM generation

@load base/protocols/ssl
@load base/protocols/ssh
@load base/files/hash

# Basic monitoring without complex logging structures
# Zeek will automatically log SSL and SSH connections with the default policies
