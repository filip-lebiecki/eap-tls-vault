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

---

**Questions or issues?** Feel free to open an issue or watch the [YouTube tutorial](https://youtu.be/AW4vq8W8qOI?si=zT3tdbtp1L_7Is-p) for visual guidance.
