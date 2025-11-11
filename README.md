# EAP-TLS with HashiCorp Vault

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
