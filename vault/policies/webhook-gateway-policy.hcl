# Least-privilege example for the Vault Agent identity associated with
# the TRC-20 webhook gateway. Vault ACLs deny all other paths by default.
# Do not add an overlapping wildcard "deny" stanza: such rules can override
# the intended narrower grant in policy evaluation.
path "secret/data/trc20/gateway" {
  capabilities = ["read"]
}
