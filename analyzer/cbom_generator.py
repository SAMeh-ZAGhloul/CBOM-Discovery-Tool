"""
CBOM Generator - Parses Zeek logs and generates Cryptographic Bill of Materials
"""
import json
import os
import glob
from datetime import datetime
from collections import defaultdict

class CBOMGenerator:
    def __init__(self, log_path="/app/logs", cbom_path="/app/cbom"):
        self.log_path = log_path
        self.cbom_path = cbom_path
        self._seen_findings = set()
        self.cbom_data = {
            "metadata": {
                "tool": "CBOM Discovery Tool",
                "version": "1.0.0",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "format": "CBOM-1.0"
            },
            "summary": {
                "total_crypto_assets": 0,
                "total_services": 0,
                "risk_score": 0,
                "protocols": {},
                "algorithms": {},
                "key_lengths": {}
            },
            "crypto_assets": [],
            "services": [],
            "certificates": [],
            "keys": [],
            "findings": []
        }

    def parse_zeek_json_log(self, log_file):
        """Parse Zeek JSON log file"""
        entries = []
        if not os.path.exists(log_file):
            return entries

        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    entry = json.loads(line)
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue
        return entries

    def _service_from_port(self, port):
        """Map port number to service name"""
        mapping = {
            8443: "https",
            443: "https",
            22: "ssh",
            2222: "ssh",
            5432: "postgresql",
            6432: "postgresql"
        }
        return mapping.get(port, f"port-{port}")

    def _infer_key_length(self, algorithm):
        """Infer key length from algorithm name"""
        algo = str(algorithm).lower()
        # RSA key lengths
        if "rsa" in algo:
            if "4096" in algo:
                return 4096
            elif "3072" in algo:
                return 3072
            elif "2048" in algo:
                return 2048
            elif "1024" in algo:
                return 1024
            elif "512" in algo:
                return 512
            return 2048  # Default RSA assumption
        # AES key lengths
        if "aes-256" in algo or "aes256" in algo:
            return 256
        if "aes-192" in algo or "aes192" in algo:
            return 192
        if "aes-128" in algo or "aes128" in algo:
            return 128
        if "aes" in algo and "gcm" in algo:
            return 256  # Default AES-GCM
        # ECC curves
        if "p-521" in algo or "secp521r1" in algo:
            return 521
        if "p-384" in algo or "secp384r1" in algo:
            return 384
        if "p-256" in algo or "secp256r1" in algo:
            return 256
        if "secp256k1" in algo:
            return 256
        # Ed25519 / Curve25519
        if "ed25519" in algo:
            return 256
        if "curve25519" in algo or "x25519" in algo:
            return 256
        # DH groups
        if "ffdhe2048" in algo or "group14" in algo:
            return 2048
        if "ffdhe4096" in algo or "group16" in algo:
            return 4096
        return None

    def process_ssl_logs(self):
        """Process Zeek ssl.log"""
        ssl_files = glob.glob(os.path.join(self.log_path, "*ssl*.log"))
        for log_file in ssl_files:
            entries = self.parse_zeek_json_log(log_file)
            for entry in entries:
                uid = entry.get("uid", "")
                resp_p = entry.get("id.resp_p", 0)
                service = self._service_from_port(resp_p)
                version = entry.get("version", "unknown")
                cipher = entry.get("cipher", "unknown")
                curve = entry.get("curve", "")
                server_name = entry.get("server_name", "")

                # Cipher as crypto asset
                key_length = self._infer_key_length(cipher)
                if cipher and cipher != "unknown":
                    self.cbom_data["crypto_assets"].append({
                        "id": f"crypto-{len(self.cbom_data['crypto_assets'])}",
                        "type": "cipher",
                        "algorithm": cipher,
                        "protocol": "tcp",
                        "service": service,
                        "source": "ssl",
                        "confidence": "high",
                        "timestamp": entry.get("ts", ""),
                        "connection_uid": uid,
                        "key_length": key_length,
                        "hash_algorithm": None,
                        "tls_version": version,
                        "curve": curve,
                        "server_name": server_name
                    })
                    self.cbom_data["summary"]["algorithms"][cipher] = \
                        self.cbom_data["summary"]["algorithms"].get(cipher, 0) + 1
                    self.cbom_data["summary"]["protocols"]["tcp"] = \
                        self.cbom_data["summary"]["protocols"].get("tcp", 0) + 1
                    if key_length:
                        self.cbom_data["summary"]["key_lengths"][str(key_length)] = \
                            self.cbom_data["summary"]["key_lengths"].get(str(key_length), 0) + 1
                    self.assess_risk("cipher", cipher, key_length or 0)

                # TLS version as crypto asset
                if version and version != "unknown":
                    self.cbom_data["crypto_assets"].append({
                        "id": f"crypto-{len(self.cbom_data['crypto_assets'])}",
                        "type": "protocol",
                        "algorithm": version,
                        "protocol": "tcp",
                        "service": service,
                        "source": "ssl",
                        "confidence": "high",
                        "timestamp": entry.get("ts", ""),
                        "connection_uid": uid,
                        "key_length": None,
                        "hash_algorithm": None
                    })
                    self.cbom_data["summary"]["algorithms"][version] = \
                        self.cbom_data["summary"]["algorithms"].get(version, 0) + 1
                    self.assess_risk("protocol", version, 0)

                # Curve as key-exchange asset
                if curve:
                    curve_key_length = self._infer_key_length(curve)
                    self.cbom_data["crypto_assets"].append({
                        "id": f"crypto-{len(self.cbom_data['crypto_assets'])}",
                        "type": "key-exchange",
                        "algorithm": curve,
                        "protocol": "tcp",
                        "service": service,
                        "source": "ssl",
                        "confidence": "high",
                        "timestamp": entry.get("ts", ""),
                        "connection_uid": uid,
                        "key_length": curve_key_length,
                        "hash_algorithm": None
                    })
                    self.cbom_data["summary"]["algorithms"][curve] = \
                        self.cbom_data["summary"]["algorithms"].get(curve, 0) + 1
                    if curve_key_length:
                        self.cbom_data["summary"]["key_lengths"][str(curve_key_length)] = \
                            self.cbom_data["summary"]["key_lengths"].get(str(curve_key_length), 0) + 1

    def process_crypto_logs(self):
        """Process legacy crypto.log and any other crypto files"""
        crypto_files = glob.glob(os.path.join(self.log_path, "*crypto*.log"))

        assets = defaultdict(lambda: {"count": 0, "services": set(), "connections": set()})

        for log_file in crypto_files:
            entries = self.parse_zeek_json_log(log_file)
            for entry in entries:
                algo = entry.get("algorithm", "unknown")
                crypto_type = entry.get("crypto_type", "unknown")
                service = entry.get("service", "unknown")
                proto = entry.get("proto", "unknown")
                uid = entry.get("uid", "")

                key = f"{crypto_type}:{algo}"
                assets[key]["count"] += 1
                assets[key]["services"].add(service)
                assets[key]["connections"].add(uid)
                assets[key]["type"] = crypto_type
                assets[key]["algorithm"] = algo
                assets[key]["protocol"] = proto

                # Add to crypto assets list
                self.cbom_data["crypto_assets"].append({
                    "id": f"crypto-{len(self.cbom_data['crypto_assets'])}",
                    "type": crypto_type,
                    "algorithm": algo,
                    "protocol": proto,
                    "service": service,
                    "source": entry.get("source", "unknown"),
                    "confidence": entry.get("confidence", "medium"),
                    "timestamp": entry.get("ts", ""),
                    "connection_uid": uid,
                    "key_length": entry.get("key_length", None),
                    "hash_algorithm": entry.get("hash_algorithm", None)
                })

                # Update summary
                self.cbom_data["summary"]["algorithms"][algo] = \
                    self.cbom_data["summary"]["algorithms"].get(algo, 0) + 1
                self.cbom_data["summary"]["protocols"][proto] = \
                    self.cbom_data["summary"]["protocols"].get(proto, 0) + 1

                # Risk assessment
                self.assess_risk(crypto_type, algo, entry.get("key_length", 0))

        return assets

    def process_certificate_logs(self):
        """Process certificate logs from Zeek"""
        cert_files = glob.glob(os.path.join(self.log_path, "*cert*.log"))
        cert_files += glob.glob(os.path.join(self.log_path, "*x509*.log"))

        for log_file in cert_files:
            entries = self.parse_zeek_json_log(log_file)
            for entry in entries:
                cert = {
                    "id": f"cert-{len(self.cbom_data['certificates'])}",
                    "subject": entry.get("subject", ""),
                    "issuer": entry.get("issuer", ""),
                    "serial": entry.get("serial", ""),
                    "key_algorithm": entry.get("key_alg", ""),
                    "signature_algorithm": entry.get("sig_alg", ""),
                    "key_length": entry.get("key_length", 0),
                    "valid_from": entry.get("not_valid_before", ""),
                    "valid_until": entry.get("not_valid_after", ""),
                    "sha1_fingerprint": entry.get("sha1", ""),
                    "sha256_fingerprint": entry.get("sha256", ""),
                    "source": "x509"
                }
                self.cbom_data["certificates"].append(cert)

                # Check certificate expiry
                self.check_cert_expiry(cert)

    def process_files_logs(self):
        """Process files.log for hash algorithm usage"""
        files_logs = glob.glob(os.path.join(self.log_path, "*files*.log"))
        seen_hash_algos = set()

        for log_file in files_logs:
            entries = self.parse_zeek_json_log(log_file)
            for entry in entries:
                analyzers = entry.get("analyzers", [])
                uid = entry.get("uid", "")
                ts = entry.get("ts", "")
                mime_type = entry.get("mime_type", "")
                source = entry.get("source", "unknown")

                # Track hash algorithms used for file analysis
                # Only create one asset per unique hash algorithm (deduplicated)
                for analyzer in analyzers:
                    algo = analyzer.lower()
                    if algo in ["md5", "sha1", "sha256"]:
                        asset_type = "hash"
                        algo_upper = algo.upper()
                        # Deduplicate: only add one asset per unique hash algorithm
                        if algo_upper in seen_hash_algos:
                            continue
                        seen_hash_algos.add(algo_upper)

                        self.cbom_data["crypto_assets"].append({
                            "id": f"crypto-{len(self.cbom_data['crypto_assets'])}",
                            "type": asset_type,
                            "algorithm": algo_upper,
                            "protocol": "tcp",
                            "service": source.lower(),
                            "source": "files",
                            "confidence": "high",
                            "timestamp": ts,
                            "connection_uid": uid,
                            "key_length": None,
                            "hash_algorithm": algo_upper,
                            "mime_type": mime_type
                        })
                        self.cbom_data["summary"]["algorithms"][algo_upper] = \
                            self.cbom_data["summary"]["algorithms"].get(algo_upper, 0) + 1
                        # Don't assess risk for file hash algorithms - they're used for
                        # file identification, not cryptographic security purposes

    def generate_certificates_from_ssl(self):
        """Generate synthetic certificate entries from SSL log data when x509 logs are unavailable"""
        ssl_files = glob.glob(os.path.join(self.log_path, "*ssl*.log"))
        seen_certs = set()

        for log_file in ssl_files:
            entries = self.parse_zeek_json_log(log_file)
            for entry in entries:
                server_name = entry.get("server_name", "")
                resp_p = entry.get("id.resp_p", 0)
                uid = entry.get("uid", "")

                if not server_name:
                    continue

                # Create a unique key for this certificate
                cert_key = f"{server_name}:{resp_p}"
                if cert_key in seen_certs:
                    continue
                seen_certs.add(cert_key)

                # Map port to service for certificate subject
                service = self._service_from_port(resp_p)
                subject_cn = server_name if server_name else f"{service}-service"

                # Determine key algorithm from cipher/curve
                cipher = entry.get("cipher", "")
                curve = entry.get("curve", "")
                version = entry.get("version", "")

                key_alg = "RSA"
                key_length = 2048
                if curve:
                    if "25519" in curve.lower():
                        key_alg = "EdDSA"
                        key_length = 256
                    elif "secp" in curve.lower():
                        key_alg = "ECDSA"
                        if "256" in curve:
                            key_length = 256
                        elif "384" in curve:
                            key_length = 384
                        elif "521" in curve:
                            key_length = 521

                # Infer signature algorithm
                sig_alg = f"{key_alg}withSHA256"
                if version == "TLSv13":
                    sig_alg = f"{key_alg}withRSA-PSS" if key_alg == "RSA" else f"{key_alg}withSHA256"

                cert = {
                    "id": f"cert-{len(self.cbom_data['certificates'])}",
                    "subject": f"/CN={subject_cn}/O=CBOM Demo/C=US",
                    "issuer": "/CN=CBOM Demo CA/O=CBOM Demo/C=US",
                    "serial": uid[:16] if uid else f"{len(self.cbom_data['certificates']):04x}",
                    "key_algorithm": key_alg,
                    "signature_algorithm": sig_alg,
                    "key_length": key_length,
                    "valid_from": entry.get("ts", ""),
                    "valid_until": "",
                    "sha1_fingerprint": "",
                    "sha256_fingerprint": "",
                    "source": "ssl-inferred",
                    "server_name": server_name,
                    "service": service
                }
                self.cbom_data["certificates"].append(cert)

    def process_ssh_logs(self):
        """Process SSH logs from Zeek ssh.log"""
        ssh_files = glob.glob(os.path.join(self.log_path, "*ssh*.log"))

        for log_file in ssh_files:
            entries = self.parse_zeek_json_log(log_file)
            for entry in entries:
                uid = entry.get("uid", "")
                ts = entry.get("ts", "")

                # Host key algorithm
                host_key_alg = entry.get("host_key_alg", "")
                if host_key_alg:
                    self.cbom_data["keys"].append({
                        "id": f"ssh-{len(self.cbom_data['keys'])}",
                        "host_key": entry.get("host_key_fingerprint", ""),
                        "client_key": "",
                        "algorithm": host_key_alg,
                        "source": "ssh",
                        "timestamp": ts
                    })

                # Cipher algorithm
                cipher_alg = entry.get("cipher_alg", "")
                if cipher_alg:
                    cipher_key_length = self._infer_key_length(cipher_alg)
                    self.cbom_data["crypto_assets"].append({
                        "id": f"crypto-{len(self.cbom_data['crypto_assets'])}",
                        "type": "cipher",
                        "algorithm": cipher_alg,
                        "protocol": "tcp",
                        "service": "ssh",
                        "source": "ssh",
                        "confidence": "high",
                        "timestamp": ts,
                        "connection_uid": uid,
                        "key_length": cipher_key_length,
                        "hash_algorithm": None
                    })
                    self.cbom_data["summary"]["algorithms"][cipher_alg] = \
                        self.cbom_data["summary"]["algorithms"].get(cipher_alg, 0) + 1
                    self.cbom_data["summary"]["protocols"]["tcp"] = \
                        self.cbom_data["summary"]["protocols"].get("tcp", 0) + 1
                    if cipher_key_length:
                        self.cbom_data["summary"]["key_lengths"][str(cipher_key_length)] = \
                            self.cbom_data["summary"]["key_lengths"].get(str(cipher_key_length), 0) + 1
                    self.assess_risk("cipher", cipher_alg, cipher_key_length or 0)

                # MAC algorithm
                mac_alg = entry.get("mac_alg", "")
                if mac_alg:
                    self.cbom_data["crypto_assets"].append({
                        "id": f"crypto-{len(self.cbom_data['crypto_assets'])}",
                        "type": "mac",
                        "algorithm": mac_alg,
                        "protocol": "tcp",
                        "service": "ssh",
                        "source": "ssh",
                        "confidence": "high",
                        "timestamp": ts,
                        "connection_uid": uid,
                        "key_length": None,
                        "hash_algorithm": None
                    })
                    self.cbom_data["summary"]["algorithms"][mac_alg] = \
                        self.cbom_data["summary"]["algorithms"].get(mac_alg, 0) + 1
                    self.assess_risk("mac", mac_alg, 0)

                # Key exchange algorithm
                kex_alg = entry.get("kex_alg", "")
                if kex_alg:
                    kex_key_length = self._infer_key_length(kex_alg)
                    self.cbom_data["crypto_assets"].append({
                        "id": f"crypto-{len(self.cbom_data['crypto_assets'])}",
                        "type": "key-exchange",
                        "algorithm": kex_alg,
                        "protocol": "tcp",
                        "service": "ssh",
                        "source": "ssh",
                        "confidence": "high",
                        "timestamp": ts,
                        "connection_uid": uid,
                        "key_length": kex_key_length,
                        "hash_algorithm": None
                    })
                    self.cbom_data["summary"]["algorithms"][kex_alg] = \
                        self.cbom_data["summary"]["algorithms"].get(kex_alg, 0) + 1
                    if kex_key_length:
                        self.cbom_data["summary"]["key_lengths"][str(kex_key_length)] = \
                            self.cbom_data["summary"]["key_lengths"].get(str(kex_key_length), 0) + 1
                    self.assess_risk("key-exchange", kex_alg, kex_key_length or 0)

                # SSH version
                ssh_version = entry.get("version", "")
                if ssh_version:
                    version_str = f"SSH-{ssh_version}"
                    self.cbom_data["crypto_assets"].append({
                        "id": f"crypto-{len(self.cbom_data['crypto_assets'])}",
                        "type": "protocol",
                        "algorithm": version_str,
                        "protocol": "tcp",
                        "service": "ssh",
                        "source": "ssh",
                        "confidence": "high",
                        "timestamp": ts,
                        "connection_uid": uid,
                        "key_length": None,
                        "hash_algorithm": None
                    })
                    self.cbom_data["summary"]["algorithms"][version_str] = \
                        self.cbom_data["summary"]["algorithms"].get(version_str, 0) + 1

    def assess_risk(self, crypto_type, algorithm, key_length):
        """Assess cryptographic risk"""
        risk_level = "low"
        finding = None
        finding_key = None

        # Weak algorithms
        weak_algos = ["md5", "sha1", "rc4", "des", "3des", "dsa"]
        deprecated_algos = ["rsa", "dh"]
        weak_tls = ["tlsv10", "tlsv11", "sslv2", "sslv3"]

        algo_lower = algorithm.lower()

        if any(w in algo_lower for w in weak_algos):
            risk_level = "critical"
            finding = f"Weak/deprecated algorithm detected: {algorithm}"
            finding_key = f"weak:{algorithm}"
        elif any(t in algo_lower for t in weak_tls):
            risk_level = "critical"
            finding = f"Insecure TLS/SSL version detected: {algorithm}"
            finding_key = f"tls:{algorithm}"
        elif any(d in algo_lower for d in deprecated_algos):
            if key_length and key_length < 2048:
                risk_level = "high"
                finding = f"Short key length for {algorithm}: {key_length} bits"
                finding_key = f"short_key:{algorithm}:{key_length}"
            else:
                risk_level = "medium"
                finding = f"Legacy algorithm in use: {algorithm}"
                finding_key = f"legacy:{algorithm}"

        # Check key lengths
        # Per README: <128 = critical, 128-255 = medium, >=256 = low
        if crypto_type in ["encryption", "key-exchange", "cipher"] and key_length:
            if key_length < 128:
                risk_level = "critical"
                finding = f"Inadequate key length: {key_length} bits"
                finding_key = f"inadequate_key:{key_length}"
            elif key_length < 256:
                risk_level = "medium"
                finding = f"Below recommended key length: {key_length} bits"
                finding_key = f"below_rec_key:{key_length}"

        if finding and finding_key:
            # Deduplicate findings
            if finding_key in self._seen_findings:
                return
            self._seen_findings.add(finding_key)

            self.cbom_data["findings"].append({
                "id": f"finding-{len(self.cbom_data['findings'])}",
                "severity": risk_level,
                "type": "algorithm_risk",
                "description": finding,
                "algorithm": algorithm,
                "crypto_type": crypto_type,
                "recommendation": self.get_recommendation(algorithm, crypto_type)
            })

    def check_cert_expiry(self, cert):
        """Check if certificate is expired or near expiry"""
        try:
            if cert.get("valid_until"):
                # Parse Zeek timestamp format
                expiry = datetime.fromisoformat(cert["valid_until"].replace('Z', '+00:00'))
                now = datetime.now(expiry.tzinfo)
                days_until = (expiry - now).days

                if days_until < 0:
                    self.cbom_data["findings"].append({
                        "id": f"finding-{len(self.cbom_data['findings'])}",
                        "severity": "high",
                        "type": "certificate_expired",
                        "description": f"Certificate expired {abs(days_until)} days ago: {cert['subject']}",
                        "subject": cert["subject"],
                        "recommendation": "Renew certificate immediately"
                    })
                elif days_until < 30:
                    self.cbom_data["findings"].append({
                        "id": f"finding-{len(self.cbom_data['findings'])}",
                        "severity": "medium",
                        "type": "certificate_expiring",
                        "description": f"Certificate expires in {days_until} days: {cert['subject']}",
                        "subject": cert["subject"],
                        "recommendation": "Plan certificate renewal"
                    })
        except:
            pass

    def get_recommendation(self, algorithm, crypto_type):
        """Get remediation recommendation"""
        recommendations = {
            "md5": "Replace MD5 with SHA-256 or SHA-3",
            "sha1": "Replace SHA-1 with SHA-256 or SHA-3",
            "rc4": "Disable RC4, use AES-GCM or ChaCha20-Poly1305",
            "des": "Replace DES with AES-256-GCM",
            "3des": "Replace 3DES with AES-256-GCM",
            "rsa": "Consider migrating to ECDSA or Ed25519 for better performance",
            "dh": "Use ECDHE with Curve25519 for key exchange",
            "tlsv10": "Upgrade to TLS 1.2 or TLS 1.3",
            "tlsv11": "Upgrade to TLS 1.2 or TLS 1.3",
            "sslv2": "Disable SSLv2 immediately",
            "sslv3": "Disable SSLv3 immediately"
        }

        algo_lower = algorithm.lower()
        for key, rec in recommendations.items():
            if key in algo_lower:
                return rec

        return "Review algorithm against current NIST/BSI recommendations"

    def generate_services(self):
        """Generate service inventory from crypto assets"""
        services = defaultdict(lambda: {"protocols": set(), "algorithms": set(), "assets": 0})

        for asset in self.cbom_data["crypto_assets"]:
            svc = asset["service"]
            services[svc]["protocols"].add(asset["protocol"])
            services[svc]["algorithms"].add(asset["algorithm"])
            services[svc]["assets"] += 1

        for svc_name, svc_data in services.items():
            self.cbom_data["services"].append({
                "name": svc_name,
                "protocols": list(svc_data["protocols"]),
                "algorithms": list(svc_data["algorithms"]),
                "asset_count": svc_data["assets"]
            })

    def calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        score = 0
        for finding in self.cbom_data["findings"]:
            if finding["severity"] == "critical":
                score += 25
            elif finding["severity"] == "high":
                score += 15
            elif finding["severity"] == "medium":
                score += 5

        self.cbom_data["summary"]["risk_score"] = min(score, 100)
        self.cbom_data["summary"]["total_crypto_assets"] = len(self.cbom_data["crypto_assets"])
        self.cbom_data["summary"]["total_services"] = len(self.cbom_data["services"])
        self.cbom_data["summary"]["total_findings"] = len(self.cbom_data["findings"])
        self.cbom_data["summary"]["total_certificates"] = len(self.cbom_data["certificates"])
        self.cbom_data["summary"]["total_keys"] = len(self.cbom_data["keys"])

    def generate(self):
        """Generate complete CBOM"""
        self.process_crypto_logs()
        self.process_ssl_logs()
        self.process_certificate_logs()
        self.generate_certificates_from_ssl()
        self.process_ssh_logs()
        self.process_files_logs()
        self.generate_services()
        self.calculate_risk_score()

        # Save CBOM
        cbom_file = os.path.join(self.cbom_path, "cbom.json")
        with open(cbom_file, 'w') as f:
            json.dump(self.cbom_data, f, indent=2)

        return self.cbom_data

    def get_summary(self):
        """Get summary statistics"""
        return self.cbom_data.get("summary", {})

    def get_findings(self):
        """Get all findings"""
        return self.cbom_data.get("findings", [])
