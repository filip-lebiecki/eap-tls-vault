vault {
  # HTTP
  # address = "http://192.168.80.83:8200"
  # or HTTPS
  address = "https://192.168.80.83:8200"
  ca_cert_file = "/etc/vault.d/ca_chain.pem"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path = "/etc/vault.d/role_id"
      secret_id_file_path = "/etc/vault.d/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/run/vault/token"
      mode = 0600
    }
  }
}

template {
  source      = "/etc/vault.d/client_cert.tpl"
  destination = "/var/lib/vault-agent/certs/client.pem"
  perms       = "0600"
}

template {
  source      = "/etc/vault.d/client_key.tpl"
  destination = "/var/lib/vault-agent/certs/client.key"
  perms       = "0600"
}
