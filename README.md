# EAP-TLS with HashiCorp Vault and FreeRADIUS

A complete guide for implementing secure WiFi authentication using EAP-TLS with HashiCorp Vault PKI backend and FreeRADIUS.

**[📺 YouTube Tutorial](https://youtu.be/AW4vq8W8qOI?si=zT3tdbtp1L_7Is-p)**

## 📖 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Architecture](#architecture)
- [Installation Steps](#installation-steps)
  - [HashiCorp Vault Setup](#install-hashicorp-vault)
  - [PKI Configuration](#configure-ca-and-intermediate-ca)
  - [Certificate Generation](#generate-certificates)
  - [FreeRADIUS Setup](#install-freeradius)
  - [Testing](#test-freeradius)
- [Client Configuration](#client-configuration)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

## 🎯 Overview

This project demonstrates enterprise-grade WiFi security using:
- **EAP-TLS**: Mutual certificate-based authentication
- **HashiCorp Vault**: Dynamic PKI for automated certificate lifecycle management
- **FreeRADIUS**: Industry-standard RADIUS server for 802.1X authentication
- **Elliptic Curve Cryptography**: Modern, efficient cryptographic algorithms

### Why EAP-TLS?

Traditional WiFi security (WPA2-PSK) has limitations:
- ❌ Shared passwords are vulnerable to brute force attacks
- ❌ Password rotation is difficult
- ❌ No individual user accountability
- ❌ Passwords can be easily shared

EAP-TLS provides:
- ✅ **Mutual authentication** - Both client and server verify identities
- ✅ **No shared passwords** - Each client has unique certificates
- ✅ **Automated lifecycle** - Vault manages issuance, renewal, revocation
- ✅ **Individual accountability** - Each user is uniquely identified
- ✅ **Strong cryptography** - Modern EC algorithms for better performance

## 📋 Prerequisites

- Docker and Docker Compose
- `jq` for JSON processing: `apt install jq`
- `openssl` for certificate verification
- `eapol_test` for testing (from `wpa_supplicant` package)
- Basic understanding of PKI and 802.1X concepts
- WiFi access point supporting WPA2/WPA3 Enterprise

## 🏗️ Architecture

```
┌─────────────┐          ┌──────────────┐          ┌─────────────┐
│   Client    │          │   Access     │          │ FreeRADIUS  │
│  (Device)   │◄────────►│   Point      │◄────────►│   Server    │
│             │   WiFi   │  (802.1X)    │  RADIUS  │             │
└─────────────┘          └──────────────┘          └──────┬──────┘
     │                                                     │
     │  Client Certificate                      Server Certificate
     │  (EC, 30d TTL)                            (EC, 365d TTL)
     │                                                     │
     └─────────────────────────────────────────────────────┘
              HashiCorp Vault PKI Backend (Dockerized)
                   Root CA → Intermediate CA
```

## 🚀 Installation Steps

### Install HashiCorp Vault

#### 1. Create directory structure

```bash
mkdir -p vault/config vault/data vault/tls
```

#### 2. Create Vault configuration

**For testing (non-TLS):**

```hcl
# vault/config/vault.hcl

storage "raft" {
  path    = "/vault/data"
  node_id = "node1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

api_addr = "http://vault:8200"
cluster_addr = "http://vault:8201"
ui = true
disable_mlock = false
```

**For production (TLS enabled):**

```hcl
# vault/config/vault.hcl

storage "raft" {
  path    = "/vault/data"
  node_id = "node1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 0
  tls_cert_file = "/vault/tls/vault-server.pem"
  tls_key_file  = "/vault/tls/vault-server.key"
}

api_addr = "https://vault:8200"
cluster_addr = "https://vault:8201"
ui = true
disable_mlock = false
```

**Expected folder structure:**

```
vault/
├── config/
│   └── vault.hcl
├── data/
│   ├── raft/
│   └── vault.db
└── tls/
    ├── vault-server.key
    └── vault-server.pem
```

#### 3. Create Docker Compose file

```yaml
# docker-compose.yaml
services:
  vault:
    image: hashicorp/vault:latest
    container_name: vault
    ports:
      - "8200:8200"
    cap_add:
      - IPC_LOCK
    volumes:
      - ./vault/config:/vault/config
      - ./vault/data:/vault/data
      - ./vault/tls:/vault/tls
    command: vault server -config=/vault/config/vault.hcl
    environment:
      VAULT_ADDR: "http://127.0.0.1:8200"
    restart: unless-stopped
```

#### 4. Start and initialize Vault

```bash
# Start Vault server
docker compose up -d
docker ps
docker logs vault

# Initialize Vault (returns unseal keys and root token - SAVE THESE!)
docker exec -it vault vault operator init

# Unseal Vault (requires 3 different unseal keys)
docker exec -it vault vault operator unseal
docker exec -it vault vault operator unseal
docker exec -it vault vault operator unseal

# Verify Vault status
docker exec -it vault vault status
```

⚠️ **CRITICAL**: Save your unseal keys and root token securely! You'll need them after every restart.

### Configure CA and Intermediate CA

```bash
# Set Vault address and login
export VAULT_ADDR='http://127.0.0.1:8200'
vault login  # Enter your root token

# Enable PKI secrets engine for Root CA
vault secrets enable pki
vault secrets tune -max-lease-ttl="3650d" pki

# Generate Root CA with EC key
vault write -format=json pki/root/generate/internal \
  common_name="WiFi Root CA" \
  ttl=3650d \
  key_type=ec \
  key_bits=256 \
  | tee pki.json

# Extract and verify root certificate
jq -r .data.certificate pki.json | tee ca.pem
openssl x509 -in ca.pem -noout -text

# Enable Intermediate CA
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl="3650d" pki_int

# Generate Intermediate CA CSR with EC key
vault write -format=json pki_int/intermediate/generate/internal \
  common_name="WiFi Intermediate CA" \
  ttl=3650d \
  key_type=ec \
  key_bits=256 \
  | tee pki_int.json

# Extract CSR
jq -r .data.csr pki_int.json | tee pki_int.csr

# Sign Intermediate CA with Root CA
vault write -format=json pki/root/sign-intermediate \
  csr=@pki_int.csr \
  format=pem_bundle \
  ttl=3650d \
  | tee signed_int.json

# Extract and verify signed intermediate certificate
jq -r .data.certificate signed_int.json | tee ca_int.pem
openssl x509 -in ca_int.pem -noout -text

# Set signed certificate
vault write pki_int/intermediate/set-signed certificate=@ca_int.pem

# Verify certificate chain
openssl verify -CAfile ca.pem ca_int.pem

# Create certificate chain file
cat ca.pem ca_int.pem | tee ca_chain.pem

# Cleanup temporary files
rm pki.json pki_int.json pki_int.csr signed_int.json
```

### Generate Certificates

#### RADIUS Server Role and Certificate

```bash
# Create RADIUS server role with EC key type
vault write pki_int/roles/radius_role \
  allowed_domains="radius.wifi.local" \
  allow_subdomains=false \
  allow_bare_domains=true \
  allow_wildcard_certificates=false \
  enforce_hostnames=true \
  allow_any_name=false \
  allow_localhost=false \
  server_flag=true \
  client_flag=false \
  max_ttl="365d" \
  key_type=ec \
  key_bits=256

# Generate RADIUS server certificate
vault write -format=json pki_int/issue/radius_role \
  common_name="radius.wifi.local" \
  ttl="365d" \
  | tee radius.json

# Extract certificate and private key
jq -r .data.certificate radius.json | tee radius.pem
jq -r .data.private_key radius.json | tee radius.key

# Cleanup
rm radius.json
```

#### Client Role and Certificate

```bash
# Create client role with user ID restriction
vault write pki_int/roles/client_role \
  allowed_domains="client.wifi.local" \
  allowed_user_ids="client,client2" \
  allow_subdomains=false \
  allow_bare_domains=true \
  allow_wildcard_certificates=false \
  enforce_hostnames=true \
  allow_any_name=false \
  allow_localhost=false \
  server_flag=false \
  client_flag=true \
  max_ttl="30d" \
  key_type=ec \
  key_bits=256

# Generate client certificate with user ID
vault write -format=json pki_int/issue/client_role \
  common_name="client.wifi.local" \
  user_ids="client" \
  ttl="30d" \
  | tee client.json

# Extract certificate and private key
jq -r .data.certificate client.json | tee client.pem
jq -r .data.private_key client.json | tee client.key

# Verify client certificate
openssl x509 -in client.pem -noout -text

# Cleanup
rm client.json
```

💡 **Note**: Client certificates have a 30-day TTL for security. You can automate renewal using Vault's API.

### Install FreeRADIUS

#### 1. Create directory structure

```bash
mkdir -p radius/ssl/private radius/ssl/certs
```

#### 2. Copy certificates

```bash
# Copy RADIUS server private key
cp radius.key radius/ssl/private/

# Copy certificates
cp radius.pem ca_chain.pem radius/ssl/certs/

# Set proper permissions
chmod 600 radius/ssl/private/radius.key
chmod 644 radius/ssl/certs/*.pem
```

#### 3. Create FreeRADIUS configuration files

**Client configuration:**

```conf
# radius/clients.conf
client unifi {
    ipaddr = 0.0.0.0/0
    secret = testing123
    require_message_authenticator = yes
    nas_type = other
}
```

⚠️ **Security**: Change `testing123` to a strong shared secret in production!

**Virtual server configuration:**

```conf
# radius/sites-available/default
server default {
    listen {
        type = auth
        ipaddr = *
        port = 0
    }

    listen {
        type = acct
        ipaddr = *
        port = 0
    }

    authorize {
        eap {
            ok = return
        }
    }

    authenticate {
        eap
    }

    preacct {
        acct_unique
    }

    accounting {
        detail
    }

    post-auth {
        # Validate client certificate CN matches allowed patterns
        if (TLS-Client-Cert-Common-Name !~ /^(client|client2)\.wifi\.local$/) {
            reject
        }

        update {
            &reply: += &session-state:
        }

        remove_reply_message_if_eap

        Post-Auth-Type REJECT {
            remove_reply_message_if_eap
        }

        if (EAP-Key-Name && &reply:EAP-Session-Id) {
            update reply {
                &EAP-Key-Name := &reply:EAP-Session-Id
            }
        }
    }
}
```

**EAP module configuration:**

```conf
# radius/mods-available/eap
eap {
    default_eap_type = tls
    timer_expire = 60
    ignore_unknown_eap_types = no
    max_sessions = ${max_requests}

    tls-config tls-common {
        private_key_file = "/etc/ssl/private/radius.key"
        certificate_file = "/etc/ssl/certs/radius.pem"
        ca_file = "/etc/ssl/certs/ca_chain.pem"
        require_client_cert = yes
        cipher_list = "HIGH:!aNULL:!MD5"
        cipher_server_preference = no
        tls_min_version = "1.2"
        tls_max_version = "1.3"
        ecdh_curve = "prime256v1"
    }

    tls {
        tls = tls-common
    }
}
```

#### 4. Create Docker Compose file for FreeRADIUS

```yaml
# docker-compose.yaml (add this service)
services:
  freeradius:
    image: freeradius/freeradius-server:latest-alpine
    container_name: freeradius
    ports:
      - "1812:1812/udp"  # Authentication
      - "1813:1813/udp"  # Accounting
    volumes:
      - ./radius/mods-available/eap:/opt/etc/raddb/mods-available/eap:ro
      - ./radius/sites-available/default:/opt/etc/raddb/sites-available/default:ro
      - ./radius/clients.conf:/opt/etc/raddb/clients.conf:ro
      - ./radius/ssl/private:/etc/ssl/private:ro
      - ./radius/ssl/certs:/etc/ssl/certs:ro
    command: ["radiusd", "-X"]  # -X for debug mode
    restart: unless-stopped
```

#### 5. Start FreeRADIUS

```bash
docker compose up -d
docker logs -f freeradius  # Watch logs for startup
```

### Test FreeRADIUS

#### 1. Create test configuration

```conf
# eap-tls.conf
network={
    ssid="test-eap-tls"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="anonymous"
    ca_cert="ca_chain.pem"
    client_cert="client.pem"
    private_key="client.key"
    private_key_passwd=""
}
```

#### 2. Run authentication test

```bash
eapol_test -c eap-tls.conf -a 127.0.0.1 -p 1812 -s testing123 -r
```

**Expected output:**
```
SUCCESS
```

If you see `SUCCESS`, your EAP-TLS authentication is working! 🎉

## 📱 Client Configuration

### Linux (NetworkManager)

```bash
nmcli connection add type wifi ifname wlan0 con-name "WiFi-EAP-TLS" \
    802-11-wireless.ssid "YourWiFiSSID" \
    802-11-wireless-security.key-mgmt wpa-eap \
    802-1x.eap tls \
    802-1x.identity "client" \
    802-1x.ca-cert /path/to/ca_chain.pem \
    802-1x.client-cert /path/to/client.pem \
    802-1x.private-key /path/to/client.key
```

### Windows

1. Import `ca_chain.pem` to **Trusted Root Certification Authorities**
2. Create PKCS#12 bundle:
   ```bash
   openssl pkcs12 -export -out client.p12 \
     -inkey client.key -in client.pem \
     -certfile ca_chain.pem
   ```
3. Import `client.p12` to **Personal** certificate store
4. WiFi Settings:
   - Security: WPA2/WPA3 Enterprise
   - Authentication: Microsoft: Smart Card or other certificate
   - Select your client certificate

### macOS

1. Import `ca_chain.pem` to Keychain (mark as trusted for 802.1X)
2. Create PKCS#12 bundle (same as Windows)
3. Import `client.p12` to Keychain
4. WiFi → Advanced → 802.1X → TLS

### Android/iOS

1. Create PKCS#12 bundle:
   ```bash
   openssl pkcs12 -export -out client.p12 \
     -inkey client.key -in client.pem \
     -certfile ca_chain.pem -name "WiFi Client"
   ```
2. Transfer `client.p12` to device
3. Import certificate (Settings → Security)
4. WiFi Settings:
   - EAP method: TLS
   - CA certificate: Use system certificates
   - User certificate: Select imported certificate

## 🔧 Troubleshooting

### Common Issues

**"Certificate verification failed"**
```bash
# Verify certificate chain
openssl verify -CAfile ca_chain.pem client.pem

# Check certificate dates
openssl x509 -in client.pem -noout -dates

# Ensure proper permissions
chmod 600 client.key
chmod 644 client.pem ca_chain.pem
```

**"TLS handshake failed"**
- Check FreeRADIUS logs: `docker logs -f freeradius`
- Verify cipher compatibility in EAP configuration
- Ensure TLS versions match (min 1.2)

**"Authentication rejected"**
- Verify CN matches regex in `post-auth` section
- Check user_ids in certificate matches allowed_user_ids
- Review FreeRADIUS debug output

**Vault is sealed after restart**
```bash
# Unseal with 3 keys
docker exec -it vault vault operator unseal
docker exec -it vault vault operator unseal
docker exec -it vault vault operator unseal
```

### Debug Commands

```bash
# Test certificate chain
openssl verify -CAfile ca.pem ca_int.pem
openssl verify -CAfile ca_chain.pem client.pem

# View certificate details
openssl x509 -in client.pem -noout -text | grep -A2 "Subject:"

# Check RADIUS server response
radtest -x user password 127.0.0.1 0 testing123

# Watch FreeRADIUS logs in real-time
docker logs -f freeradius
```

## 🔒 Security Considerations

### Production Checklist

- [ ] **Use TLS for Vault**: Enable TLS in `vault.hcl`
- [ ] **Change default secrets**: Update RADIUS shared secret
- [ ] **Implement Vault policies**: Restrict certificate issuance
- [ ] **Enable audit logging**: Track certificate operations
- [ ] **Short certificate TTLs**: 30 days for clients, 365 for servers
- [ ] **Automate renewal**: Script certificate lifecycle
- [ ] **Secure private keys**: Proper file permissions (600)
- [ ] **Network segmentation**: Isolate RADIUS in management VLAN
- [ ] **Monitor authentication**: Enable RADIUS accounting
- [ ] **Regular backups**: Backup Vault data and unseal keys

### Best Practices

1. **Certificate Lifecycle**
   - Automate client certificate renewal before expiration
   - Monitor certificate expiry with Vault's API
   - Implement certificate revocation process

2. **Access Control**
   - Limit `allowed_user_ids` to specific users
   - Use CN validation in FreeRADIUS `post-auth`
   - Implement per-user certificate tracking

3. **Key Management**
   - Never commit private keys to version control
   - Use strong passphrases for PKCS#12 exports
   - Rotate RADIUS shared secrets regularly

4. **Monitoring**
   - Enable FreeRADIUS accounting logs
   - Monitor failed authentication attempts
   - Alert on certificate expiration

## 📚 Additional Resources

- [HashiCorp Vault PKI Documentation](https://developer.hashicorp.com/vault/docs/secrets/pki)
- [FreeRADIUS EAP Configuration](https://wiki.freeradius.org/config/Eap-tls)
- [RFC 5216 - EAP-TLS Authentication](https://datatracker.ietf.org/doc/html/rfc5216)
- [IEEE 802.1X Standard](https://standards.ieee.org/standard/802_1X-2020.html)

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📝 License

MIT License - Feel free to use and modify for your needs.

## ⚠️ Disclaimer

This setup is for educational and demonstration purposes. Always conduct thorough security audits and testing before deploying in production environments.

# Automated Certificate Lifecycle with Vault Agent

## 🎯 Overview

The previous setup worked great for manually issuing certificates, but had a critical flaw: **human intervention**. With 30-day certificate validity, every device needs manual renewal every month. This doesn't scale beyond a lab environment.

**Vault Agent solves this by:**
- ✅ Automatically fetching certificates from Vault
- ✅ Proactively renewing certificates before expiration
- ✅ Managing authentication tokens without manual intervention
- ✅ Running as a background service on each endpoint
- ✅ Operating securely over TLS

## 📋 Prerequisites

- Completed HashiCorp Vault and FreeRADIUS setup
- Ubuntu 24.04 (or similar Linux distribution)
- Root or sudo access on client machines
- TLS-enabled Vault server (covered in this guide)

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Client Device (Laptop/Server)                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Vault Agent (systemd service)                     │  │
│  │  - Authenticates via AppRole                       │  │
│  │  - Manages token lifecycle                         │  │
│  │  - Fetches & renews certificates                   │  │
│  └────────────────┬───────────────────────────────────┘  │
│                   │                                       │
│  ┌────────────────▼───────────────────────────────────┐  │
│  │  /var/lib/vault-agent/certs/                       │  │
│  │  - client.pem (auto-renewed)                       │  │
│  │  - client.key (auto-renewed)                       │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────┬───────────────────────────────────┘
                       │ HTTPS (TLS)
                       │ AppRole Auth
                       │ Certificate Requests
                       ▼
        ┌──────────────────────────────┐
        │  HashiCorp Vault Server      │
        │  - Issues certificates       │
        │  - Validates AppRole         │
        │  - Enforces policies         │
        └──────────────────────────────┘
```

## 🔄 Certificate Renewal Triggers

Vault Agent automatically renews certificates in three scenarios:

1. **Agent Restart**: Certificate is immediately renewed when the service restarts
2. **Validity Threshold**: Renews when certificate reaches 90% of its validity period
   - For 30-day cert: renews 3 days before expiration
   - Provides safety buffer for network issues or failures
3. **Token Max TTL**: Forces renewal when authentication token hits maximum lifetime

## 🚀 Installation Steps

### 1. Install Vault Binary on Client

```bash
# Check OS version
lsb_release -a

# Add HashiCorp repository
wget -O- https://apt.releases.hashicorp.com/gpg | \
  gpg --dearmor | \
  sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/hashicorp.list

# Install Vault
sudo apt update && sudo apt install vault

# Verify installation
vault --version
```

### 2. Configure Vault Client

```bash
# Set Vault server address
export VAULT_ADDR='http://192.168.12.230:8200'

# Check Vault status (no auth required)
vault status

# Login with root token (for setup only)
vault login
# Enter your root token

# Verify authentication
vault token lookup
cat ~/.vault-token
```

### 3. Test Manual Certificate Operations

```bash
# Fetch Root CA
vault read -format=json pki/cert/ca | \
  jq -r .data.certificate | \
  tee ca.pem

# Fetch Intermediate CA
vault read -format=json pki_int/cert/ca | \
  jq -r .data.certificate | \
  tee ca_int.pem

# Create CA chain
cat ca.pem ca_int.pem | tee ca_chain.pem

# List available roles
vault list pki_int/roles

# View role details
vault read pki_int/roles/client_role

# Issue a client certificate manually
vault write -format=json pki_int/issue/client_role \
  common_name="client.wifi.local" \
  user_ids="client" \
  ttl="30d" | \
  tee client.json | jq

# Extract certificate and key
jq -r .data.certificate client.json | tee client.pem
jq -r .data.private_key client.json | tee client.key

# Verify certificate
openssl x509 -in client.pem -noout -text

# Cleanup
rm client.json
```

## 🔐 Security Configuration

### 4. Create Vault Policy

Policies enforce least-privilege access control. Each client should only be able to issue their own certificates.

**Create policy file:**

```bash
cat > client-policy.hcl <<'EOF'
# Allow issuing certificates using client_role
path "pki_int/issue/client_role" {
  capabilities = ["create", "update"]
}

# Allow reading root CA certificate
path "pki/cert/ca" {
  capabilities = ["read"]
}

# Allow reading intermediate CA certificate
path "pki_int/cert/ca" {
  capabilities = ["read"]
}
EOF
```

**Apply policy:**

```bash
# Create policy in Vault
vault policy write client-policy client-policy.hcl

# Verify policy was created
vault policy list
vault policy read client-policy
```

**Test policy restrictions:**

```bash
# Create token with policy restriction
vault token create \
  -policy=client-policy \
  -ttl=1h \
  -explicit-max-ttl=24h

# Copy the token and login in a new terminal
export VAULT_ADDR='http://192.168.12.230:8200'
vault login
# Paste the token

# Test allowed operations
vault read pki_int/cert/ca  # Should work

# Test denied operations
vault list pki_int/certs  # Should fail: permission denied

# Test certificate issuance (allowed)
vault write -format=json pki_int/issue/client_role \
  common_name="client.wifi.local" \
  user_ids="client" \
  ttl="30d" | tee client.json | jq

# Try to issue RADIUS server cert (denied)
vault write -format=json pki_int/issue/radius_role \
  common_name="radius.wifi.local" \
  ttl="30d"  # Should fail: permission denied
```

### 5. Configure AppRole Authentication

AppRole provides secure, automated authentication for machines without human intervention.

```bash
# Enable AppRole auth method
vault auth enable approle
vault auth list

# Create AppRole with client policy
vault write auth/approle/role/app-role \
  policies=client-policy \
  token_ttl=1h \
  token_max_ttl=24h

# Verify AppRole was created
vault list auth/approle/role

# Get Role ID (stable, like a username)
vault read auth/approle/role/app-role/role-id
# Save this output

# Generate Secret ID (dynamic, like a password)
vault write -f auth/approle/role/app-role/secret-id
# Save this output
```

**Test AppRole authentication:**

```bash
# In a new terminal, authenticate using AppRole
ROLE_ID="<your-role-id>"
SECRET_ID="<your-secret-id>"

vault write auth/approle/login \
  role_id="$ROLE_ID" \
  secret_id="$SECRET_ID"

# Login with the returned token
vault login
# Paste the token

# Test operations
vault read pki_int/cert/ca  # Should work
vault token renew  # Should work
vault write -format=json pki_int/issue/client_role \
  common_name="client.wifi.local" \
  user_ids="client" \
  ttl="30d" | tee client.json | jq  # Should work
```

### 6. Enable TLS on Vault Server

⚠️ **CRITICAL**: Never send secrets over unencrypted HTTP in production!

**Create server certificate role:**

```bash
# Create dedicated server role for Vault
vault write pki_int/roles/server_role \
  max_ttl="365d" \
  key_type=ec \
  key_bits=256 \
  allow_ip_sans=true \
  allowed_domains="vault.local" \
  allowed_bare_domains=true

# Issue server certificate (replace IP with your Vault server IP)
vault write -format=json pki_int/issue/server_role \
  common_name="vault.local" \
  ip_sans="192.168.12.230" \
  ttl="365d" | \
  tee server.json

# Extract certificate and key
jq -r .data.certificate server.json | tee server.pem
jq -r .data.private_key server.json | tee server.key
rm server.json

# Copy to Vault server TLS directory
cp server.key server.pem vault/tls/
chmod 600 vault/tls/server.key
chmod 644 vault/tls/server.pem
```

**Update Vault server configuration:**

```bash
# Edit vault/config/vault.hcl
cat > vault/config/vault.hcl <<'EOF'
storage "raft" {
  path    = "/vault/data"
  node_id = "node1"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = 0
  tls_cert_file = "/vault/tls/server.pem"
  tls_key_file  = "/vault/tls/server.key"
}

api_addr     = "https://vault:8200"
cluster_addr = "https://vault:8201"
ui           = true
disable_mlock = false
EOF

# Restart Vault server
docker compose restart vault
docker logs vault
```

**Test TLS connection:**

```bash
# Try HTTP (should fail)
export VAULT_ADDR=http://192.168.12.230:8200
vault status  # Error: connection refused

# Try HTTPS without CA (should fail)
export VAULT_ADDR=https://192.168.12.230:8200
vault status  # Error: certificate validation failed

# Try HTTPS with CA chain (should work)
export VAULT_ADDR=https://192.168.12.230:8200
export VAULT_CACERT=/path/to/ca_chain.pem
vault status  # Success!
```

## 🤖 Vault Agent Setup

### 7. Prepare Agent Directory Structure

```bash
# Create token storage directory
sudo mkdir -p /run/vault/
sudo chown vault: /run/vault/
sudo chmod 700 /run/vault/

# Create certificate output directory
sudo mkdir -p /var/lib/vault-agent/certs/
sudo chown -R vault: /var/lib/vault-agent/certs/
sudo chmod 755 /var/lib/vault-agent/certs/

# Create configuration directory
sudo mkdir -p /etc/vault.d/
```

### 8. Configure Vault Agent

**Create AppRole credentials:**

```bash
# Get Role ID from Vault
vault read auth/approle/role/app-role/role-id

# Save Role ID to file
sudo bash -c 'cat > /etc/vault.d/role_id <<EOF
<your-role-id>
EOF'

# Generate and save Secret ID
vault write -f auth/approle/role/app-role/secret-id

sudo bash -c 'cat > /etc/vault.d/secret_id <<EOF
<your-secret-id>
EOF'

# Secure credentials
sudo chmod 600 /etc/vault.d/role_id
sudo chmod 600 /etc/vault.d/secret_id
sudo chown vault: /etc/vault.d/role_id
sudo chown vault: /etc/vault.d/secret_id
```

**Create main Agent configuration:**

```bash
sudo cat > /etc/vault.d/vault-agent.hcl <<'EOF'
vault {
  address = "https://192.168.12.230:8200"
  ca_cert = "/etc/vault.d/ca_chain.pem"
}

auto_auth {
  method {
    type = "approle"
    
    config = {
      role_id_file_path   = "/etc/vault.d/role_id"
      secret_id_file_path = "/etc/vault.d/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink {
    type = "file"
    config = {
      path = "/run/vault/token"
      mode = 0600
    }
  }
}

template {
  source      = "/etc/vault.d/client_cert.tpl"
  destination = "/var/lib/vault-agent/certs/client.pem"
  perms       = 0644
}

template {
  source      = "/etc/vault.d/client_key.tpl"
  destination = "/var/lib/vault-agent/certs/client.key"
  perms       = 0600
}
EOF

sudo chown vault: /etc/vault.d/vault-agent.hcl
sudo chmod 640 /etc/vault.d/vault-agent.hcl
```

**Copy CA chain to agent:**

```bash
# Copy CA chain for TLS verification
sudo cp ca_chain.pem /etc/vault.d/
sudo chmod 644 /etc/vault.d/ca_chain.pem
```

### 9. Create Certificate Templates

**Client certificate template:**

```bash
sudo cat > /etc/vault.d/client_cert.tpl <<'EOF'
{{ with secret "pki_int/issue/client_role" "common_name=client.wifi.local" "user_ids=client" "ttl=30d" }}
{{ .Data.certificate }}
{{ end }}
EOF

sudo chmod 644 /etc/vault.d/client_cert.tpl
```

**Private key template:**

```bash
sudo cat > /etc/vault.d/client_key.tpl <<'EOF'
{{ with secret "pki_int/issue/client_role" "common_name=client.wifi.local" "user_ids=client" "ttl=30d" }}
{{ .Data.private_key }}
{{ end }}
EOF

sudo chmod 644 /etc/vault.d/client_key.tpl
```

### 10. Create Systemd Service

**Service unit file:**

```bash
sudo cat > /usr/lib/systemd/system/vault-agent.service <<'EOF'
[Unit]
Description=Vault Agent
Documentation=https://www.vaultproject.io/docs/agent
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault.d/vault-agent.hcl

[Service]
Type=notify
EnvironmentFile=/etc/vault.d/vault-agent.env
User=vault
Group=vault
ExecStart=/usr/bin/vault agent -config=/etc/vault.d/vault-agent.hcl
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
KillSignal=SIGTERM
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
```

**Environment file:**

```bash
sudo cat > /etc/vault.d/vault-agent.env <<'EOF'
VAULT_ADDR=https://192.168.12.230:8200
VAULT_CACERT=/etc/vault.d/ca_chain.pem
EOF

sudo chmod 644 /etc/vault.d/vault-agent.env
```

**Verify configuration structure:**

```bash
tree /etc/vault.d/
# Expected output:
# /etc/vault.d/
# ├── ca_chain.pem
# ├── client_cert.tpl
# ├── client_key.tpl
# ├── role_id
# ├── secret_id
# ├── vault-agent.env
# └── vault-agent.hcl
```

### 11. Start Vault Agent Service

```bash
# Reload systemd daemon
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable vault-agent

# Start service
sudo systemctl start vault-agent

# Check status
sudo systemctl status vault-agent

# View logs
journalctl -u vault-agent -f
```

### 12. Verify Agent Operation

```bash
# Check if certificates were created
ls -la /var/lib/vault-agent/certs/

# View token (should exist after first auth)
sudo cat /run/vault/token

# Lookup token details (from authenticated terminal)
vault token lookup $(sudo cat /run/vault/token)

# Verify certificate validity
openssl x509 -in /var/lib/vault-agent/certs/client.pem -noout -text
openssl x509 -in /var/lib/vault-agent/certs/client.pem -noout -dates

# Test certificate renewal by restarting agent
sudo systemctl restart vault-agent
openssl x509 -in /var/lib/vault-agent/certs/client.pem -noout -dates
# Note: issue date should be updated
```

## 🔍 Monitoring and Troubleshooting

### View Agent Logs

```bash
# Real-time logs
journalctl -u vault-agent -f

# Last 100 lines
journalctl -u vault-agent -n 100

# Logs since boot
journalctl -u vault-agent -b

# Filter for errors
journalctl -u vault-agent -p err
```

### Common Issues

**Agent fails to start:**
```bash
# Check configuration syntax
vault agent -config=/etc/vault.d/vault-agent.hcl -log-level=debug

# Verify file permissions
ls -la /etc/vault.d/
ls -la /run/vault/
ls -la /var/lib/vault-agent/certs/

# Check if vault user exists
id vault
```

**Authentication failures:**
```bash
# Verify AppRole credentials
vault read auth/approle/role/app-role/role-id
vault write -f auth/approle/role/app-role/secret-id

# Test manual authentication
vault write auth/approle/login \
  role_id=$(cat /etc/vault.d/role_id) \
  secret_id=$(cat /etc/vault.d/secret_id)

# Check TLS connectivity
curl --cacert /etc/vault.d/ca_chain.pem https://192.168.12.230:8200/v1/sys/health
```

**Certificate not renewing:**
```bash
# Check agent logs for renewal attempts
journalctl -u vault-agent | grep -i "renew"

# Verify token validity
vault token lookup $(sudo cat /run/vault/token)

# Force renewal by restarting agent
sudo systemctl restart vault-agent
```

## 📊 Token Lifecycle

Understanding token TTL vs Max TTL:

```
Token Created
│
├─> TTL: 1 hour (renewable)
│   │
│   ├─> Agent renews token every ~50 minutes
│   ├─> Token TTL resets to 1 hour each time
│   └─> This continues until...
│
└─> Max TTL: 24 hours (absolute limit)
    │
    └─> After 24 hours total:
        - Token can no longer be renewed
        - Agent re-authenticates with AppRole
        - New token issued with fresh 24-hour max TTL
```

**Monitor token lifecycle:**

```bash
# Watch token renewals in real-time
journalctl -u vault-agent -f | grep -i token

# Check current token details
vault token lookup $(sudo cat /run/vault/token)
```

## 🎯 Client WiFi Configuration

Now that certificates are automatically managed, configure WiFi on the client:

### Linux (NetworkManager)

```bash
nmcli connection add type wifi ifname wlan0 con-name "WiFi-EAP-TLS" \
    802-11-wireless.ssid "YourWiFiSSID" \
    802-11-wireless-security.key-mgmt wpa-eap \
    802-1x.eap tls \
    802-1x.identity "client" \
    802-1x.ca-cert /etc/vault.d/ca_chain.pem \
    802-1x.client-cert /var/lib/vault-agent/certs/client.pem \
    802-1x.private-key /var/lib/vault-agent/certs/client.key

# Connect
nmcli connection up "WiFi-EAP-TLS"
```

### Windows

1. Copy files to Windows-accessible location
2. Import `ca_chain.pem` to Trusted Root Certification Authorities
3. Create PKCS#12 bundle:
   ```bash
   openssl pkcs12 -export -out client.p12 \
     -inkey /var/lib/vault-agent/certs/client.key \
     -in /var/lib/vault-agent/certs/client.pem \
     -certfile /etc/vault.d/ca_chain.pem
   ```
4. Import `client.p12` to Personal certificate store
5. Configure WiFi with certificate authentication

## 🔒 Production Considerations

### Security Best Practices

1. **Protect AppRole Credentials**
   ```bash
   # Strict file permissions
   chmod 600 /etc/vault.d/role_id
   chmod 600 /etc/vault.d/secret_id
   chown vault: /etc/vault.d/*_id
   ```

2. **Monitor Certificate Expiry**
   ```bash
   # Create monitoring script
   cat > /usr/local/bin/check-cert-expiry.sh <<'EOF'
   #!/bin/bash
   CERT="/var/lib/vault-agent/certs/client.pem"
   EXPIRY=$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)
   EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
   NOW_EPOCH=$(date +%s)
   DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))
   
   if [ $DAYS_LEFT -lt 7 ]; then
     echo "WARNING: Certificate expires in $DAYS_LEFT days"
     exit 1
   fi
   exit 0
   EOF
   
   chmod +x /usr/local/bin/check-cert-expiry.sh
   ```

3. **Rotate Secret IDs Periodically**
   ```bash
   # Generate new Secret ID
   NEW_SECRET_ID=$(vault write -f -format=json \
     auth/approle/role/app-role/secret-id | \
     jq -r .data.secret_id)
   
   # Update file
   echo "$NEW_SECRET_ID" | sudo tee /etc/vault.d/secret_id
   
   # Restart agent
   sudo systemctl restart vault-agent
   ```

4. **Enable Audit Logging**
   ```bash
   # On Vault server
   vault audit enable file file_path=/vault/logs/audit.log
   ```

### Scaling to Multiple Clients

For multiple client devices, consider:

1. **Unique certificates per device:**
   - Use hostname in common name: `hostname.wifi.local`
   - Customize templates per device
   
2. **Configuration management:**
   - Use Ansible/Puppet to deploy Agent configuration
   - Template role_id and secret_id per host
   
3. **Centralized monitoring:**
   - Collect Agent logs to central logging system
   - Alert on authentication failures
   - Track certificate issuance/renewal

## 📚 Additional Resources

- [Vault Agent Documentation](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent)
- [AppRole Auth Method](https://developer.hashicorp.com/vault/docs/auth/approle)
- [Vault Agent Templates](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/template)
- [Vault Agent Caching](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/caching)

## 🎉 Summary

You've now implemented a fully automated certificate lifecycle management system:

✅ Certificates automatically issued and renewed  
✅ No manual intervention required  
✅ Secure AppRole authentication for machines  
✅ TLS-encrypted communication with Vault  
✅ Policy-based access control  
✅ Token lifecycle management  
✅ Production-ready security posture  

Users can now connect to WiFi without worrying about certificate expiration. The system silently manages everything in the background!

---

**Questions or issues?** Feel free to open an issue or watch the [YouTube tutorial](https://youtu.be/AW4vq8W8qOI?si=zT3tdbtp1L_7Is-p) for visual guidance.
