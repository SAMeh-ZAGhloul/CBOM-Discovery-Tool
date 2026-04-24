# Zeek local site policy
# Loaded by default

@load protocols/ssl/heartbleed
@load protocols/ssl/known-certs
@load protocols/ssh/interesting-hostnames
@load protocols/ssh/geo-data
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/interesting-hostnames
@load tuning/json-logs
@load frameworks/files/hash-all-files
@load base/files/x509

# Enable all relevant logs
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# Ignore invalid checksums (required for Docker/NAT environments)
redef ignore_checksums = T;
