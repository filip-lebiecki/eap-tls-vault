# EAP-TLS with HashiCorp Vault and FreeRadius [YouTube Video](https://youtu.be/AW4vq8W8qOI?si=zT3tdbtp1L_7Is-p)

### Install HashiCorp Vault

Create folders

`mkdir -p vault/config vault/data vault/tls`

Create configuration file (non-TLS flavor for testing)

```
# vault/config/vault.hcl

storage "raft" {
  path    = "/vault/data"
  node_id = "node1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

api_addr = "https://vault:8200"
cluster_addr = "https://vault:8201"
ui = true
disable_mlock = false
```

Create configuration file (TLS flavor for production)

```
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

Folder structure

```
$ tree vault
vault
├── config
│   └── vault.hcl
├── data
│   ├── raft  [error opening dir]
│   └── vault.db
└── tls
    ├── vault-server.key
    └── vault-server.pem
```

Create Docker Compose file

```
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

Start Vault Server

```
docker compose up -d
docker ps
docker logs vault
```

Initialize and unseal the Vault

```
docker exec -it vault vault operator init
docker exec -it vault vault operator unseal
docker exec -it vault vault operator unseal
docker exec -it vault vault operator unseal
docker exec -it vault vault status
```

### Configure CA and Intermediate CA

```
export VAULT_ADDR='http://127.0.0.1:8200'
vault login
vault secrets enable pki
vault secrets tune -max-lease-ttl="3650d" pki
vault write -format=json pki/root/generate/internal common_name="WiFi Root CA" ttl=3650d key_type=ec > pki.json
jq -r .data.certificate pki.json > ca.pem
openssl x509 -in ca.pem -noout -text
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl="3650d" pki_int
vault write -format=json pki_int/intermediate/generate/internal common_name="WiFi Intermediate CA" ttl=3850d key_type=ec > pki_int.json
jq -r .data.csr pki_int.json > pki_int.csr
vault write -format=json pki/root/sign-intermediate csr=@pki_int.csr format=pem_bundle ttl=3850d > signed_int.json
jq -r .data.certificate signed_int.json > ca_int.pem
openssl x509 -in ca_int.pem -noout -text
vault write pki_int/intermediate/set-signed certificate=@ca_int.pem
openssl verify -CAfile ca.pem ca_int.pem
cat ca.pem ca_int.pem | tee ca_chain.pem 
rm pki.json pki_int.json pki_int.csr
```

### Generate role for RADIUS and Certificate for RADIUS

```
TODO
```

### Generate role for Client and Certificate for Client

```
TODO
```

### Install FreeRadius

Create Docker Compose file

```bash
services:
  freeradius:
    image: freeradius/freeradius-server:latest-alpine
    container_name: freeradius
    ports:
      - "1812:1812/udp"
      - "1813:1813/udp"
    volumes:
      - ./radius/eap:/opt/etc/raddb/mods-available/eap:ro
      - ./radius/default:/opt/etc/raddb/sites-available/default:ro
      - ./radius/clients.conf:/opt/etc/raddb/clients.conf:ro
      - ./radius/ssl/private:/etc/ssl/private:ro
      - ./radius/ssl/certs:/etc/ssl/certs:ro
    command: ["radiusd", "-X"]
    restart: unless-stopped
```

Copy `radius.key` to `radius/ssl/private`

Copy `radius.pem` and `ca_chain.pem` to `radius/ssl/certs`

Client configuration

```
# radius/clients.conf
client unifi {
    ipaddr = 0.0.0.0
    secret = testing123
}
```

Virtual server configuration

```
# radius/default
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

RADIUS EAP configuration
```
# radius/eap
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
        cipher_list = "DEFAULT"
        cipher_server_preference = no
        tls_min_version = "1.2"
        tls_max_version = "1.2"
    }

    tls {
        tls = tls-common
    }
}
```

Start FreeRadius
```
docker compose up -d
docker logs freeradius  
```

Prepare EAP-TLS config file
```
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

Test FreeRadius

```
eapol_test -c eap-tls.conf -a 127.0.0.1 -p 1812 -s testing123 -r
```
