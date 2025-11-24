storage "raft" {
  path = "/vault/data"
  node_id = "node1"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = 1
  # To enable TLS
  # tls_disable = 0
  # tls_cert_file = "/vault/tls/server.pem"
  # tls_key_file = "/vault/tls/server.key"
}

api_addr = "https://vault:8200"
cluster_addr = "https://vault:8201"
ui = true
disable_mlock = false
