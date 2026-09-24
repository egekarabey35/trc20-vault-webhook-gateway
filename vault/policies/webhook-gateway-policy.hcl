# Yalnızca TRC-20 webhook secret'ını okuma yetkisi
path "secret/data/trc20/gateway" {
  capabilities = ["read"]
}

# Diğer hiçbir yola veya yönetimsel alana yetki verilmez
path "secret/data/*" {
  capabilities = ["deny"]
}
