-- CBOM Demo Database Initialization
-- Creates sample tables with encrypted column demonstrations

CREATE TABLE IF NOT EXISTS crypto_inventory (
    id SERIAL PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    algorithm VARCHAR(100),
    key_length INTEGER,
    protocol VARCHAR(50),
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    risk_level VARCHAR(20) CHECK (risk_level IN ('low', 'medium', 'high', 'critical'))
);

CREATE TABLE IF NOT EXISTS certificates (
    id SERIAL PRIMARY KEY,
    subject VARCHAR(500),
    issuer VARCHAR(500),
    serial_number VARCHAR(100),
    valid_from TIMESTAMP,
    valid_until TIMESTAMP,
    key_algorithm VARCHAR(50),
    key_length INTEGER,
    fingerprint_sha256 VARCHAR(64)
);

-- Insert sample data representing discovered crypto assets
INSERT INTO crypto_inventory (asset_name, algorithm, key_length, protocol, risk_level) VALUES
('Web App TLS', 'AES-256-GCM', 256, 'TLS 1.2', 'low'),
('Web App Key Exchange', 'ECDHE', 256, 'TLS 1.2', 'low'),
('SSH Host Key', 'RSA', 2048, 'SSH', 'medium'),
('SSH Session', 'AES-256-CTR', 256, 'SSH', 'low'),
('Database SSL', 'AES-256-GCM', 256, 'TLS 1.2', 'low'),
('Legacy Service', '3DES', 168, 'TLS 1.0', 'critical');

INSERT INTO certificates (subject, issuer, serial_number, valid_from, valid_until, key_algorithm, key_length, fingerprint_sha256) VALUES
('CN=sample-web-app,O=CBOM Demo,C=US', 'CN=sample-web-app,O=CBOM Demo,C=US', '123456789', NOW(), NOW() + INTERVAL '1 year', 'RSA', 2048, 'a1b2c3d4e5f6...'),
('CN=postgres-db,O=CBOM Demo,C=US', 'CN=CBOM Demo CA,O=CBOM Demo,C=US', '987654321', NOW(), NOW() + INTERVAL '2 years', 'RSA', 2048, 'f6e5d4c3b2a1...');

-- Create a function to simulate crypto operations
CREATE OR REPLACE FUNCTION encrypt_data(data TEXT, key TEXT)
RETURNS TEXT AS $$
BEGIN
    -- Simulated encryption (in real scenario, use pgcrypto)
    RETURN 'ENC:' || encode(digest(data || key, 'sha256'), 'hex');
END;
$$ LANGUAGE plpgsql;
