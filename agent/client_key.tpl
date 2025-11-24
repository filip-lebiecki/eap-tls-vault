{{ with secret "pki_int/issue/client_role" "common_name=client.wifi.local" "user_ids=client" "ttl=30d" }}
{{ .Data.private_key }}
{{ end }}
