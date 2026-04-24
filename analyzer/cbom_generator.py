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

    def process_crypto_logs(self):
        """Process crypto.log from Zeek"""
        crypto_files = glob.glob(os.path.join(self.log_path, "*crypto*.log"))
        crypto_files += glob.glob(os.path.join(self.log_path, "*ssl*.log"))

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
                self.cbom_data["summary"]["algorithms"][algo] =                     self.cbom_data["summary"]["algorithms"].get(algo, 0) + 1
                self.cbom_data["summary"]["protocols"][proto] =                     self.cbom_data["summary"]["protocols"].get(proto, 0) + 1

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

    def process_ssh_logs(self):
        """Process SSH logs"""
        ssh_files = glob.glob(os.path.join(self.log_path, "*ssh*.log"))

        for log_file in ssh_files:
            entries = self.parse_zeek_json_log(log_file)
            for entry in entries:
                ssh_entry = {
                    "id": f"ssh-{len(self.cbom_data['keys'])}",
                    "host_key": entry.get("host_key", ""),
                    "client_key": entry.get("client_key", ""),
                    "algorithm": entry.get("key_alg", ""),
                    "source": "ssh",
                    "timestamp": entry.get("ts", "")
                }
                self.cbom_data["keys"].append(ssh_entry)

    def assess_risk(self, crypto_type, algorithm, key_length):
        """Assess cryptographic risk"""
        risk_level = "low"
        finding = None

        # Weak algorithms
        weak_algos = ["md5", "sha1", "rc4", "des", "3des", "dsa"]
        deprecated_algos = ["rsa", "dh"]

        algo_lower = algorithm.lower()

        if any(w in algo_lower for w in weak_algos):
            risk_level = "critical"
            finding = f"Weak/deprecated algorithm detected: {algorithm}"
        elif any(d in algo_lower for d in deprecated_algos):
            if key_length and key_length < 2048:
                risk_level = "high"
                finding = f"Short key length for {algorithm}: {key_length} bits"
            else:
                risk_level = "medium"
                finding = f"Legacy algorithm in use: {algorithm}"

        # Check key lengths
        if crypto_type in ["encryption", "key-exchange"] and key_length:
            if key_length < 128:
                risk_level = "critical"
                finding = f"Inadequate key length: {key_length} bits"
            elif key_length < 256:
                risk_level = "medium"
                finding = f"Below recommended key length: {key_length} bits"

        if finding:
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
            "dh": "Use ECDHE with Curve25519 for key exchange"
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
        self.process_certificate_logs()
        self.process_ssh_logs()
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
