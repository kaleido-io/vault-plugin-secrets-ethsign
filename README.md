# vault-plugin-secrets-ethsign

[![Build Status](https://travis-ci.org/kaleido-io/vault-plugin-secrets-ethsign.svg?branch=master)](https://travis-ci.org/kaleido-io/vault-plugin-secrets-ethsign)
[![codecov](https://codecov.io/gh/kaleido-io/vault-plugin-secrets-ethsign/branch/master/graph/badge.svg?token=3LlJ7aSeW2)](https://codecov.io/gh/kaleido-io/vault-plugin-secrets-ethsign)

A HashiCorp Vault plugin that supports secp256k1 based signing, with an API interface that turns the vault into a software-based HSM device.

![Overview](/resources/overview.png)

The plugin only exposes the following endpoints to enable the client to generate signing keys for the secp256k1 curve suitable for signing Ethereum transactions, list existing signing keys by their names and addresses, and a `/sign` endpoint for each account. The generated private keys are saved in the vault as a secret. It never gives out the private keys.

## Build
These dependencies are needed:

* go 1.16

To build the binary:
```
make all
```

The output is `ethsign`

## Installing the Plugin on HashiCorp Vault server
The plugin must be registered and enabled on the vault server as a secret engine.

### Enabling on a dev mode server
The easiest way to try out the plugin is using a dev mode server to load it.

Download the binary: [https://www.vaultproject.io/downloads/](https://www.vaultproject.io/downloads/)

First copy the build output binary `ethsign` to the plugins folder, say `~/.vault.d/vault-plugins/`.
```
./vault server -dev -dev-plugin-dir=/Users/alice/.vault.d/vault_plugins/
```

After the dev server starts, the plugin should have already been registered in the system plugins catalog:
```
$ ./vault login <root token>
$ ./vault read sys/plugins/catalog
Key         Value
---         -----
auth        [alicloud app-id approle aws azure centrify cert cf gcp github jwt kubernetes ldap oci oidc okta pcf radius userpass]
database    [cassandra-database-plugin elasticsearch-database-plugin hana-database-plugin influxdb-database-plugin mongodb-database-plugin mssql-database-plugin mysql-aurora-database-plugin mysql-database-plugin mysql-legacy-database-plugin mysql-rds-database-plugin postgresql-database-plugin]
secret      [ad alicloud aws azure cassandra consul ethsign gcp gcpkms kv mongodb mssql mysql nomad pki postgresql rabbitmq ssh totp transit]
```

Note the `ethsign` entry in the secret section. Now it's ready to be enabled:
```
 ./vault secrets enable -path=ethereum -description="Ethereum Wallet" -plugin-name=ethsign plugin
```

To verify the new secret engine based on the plugin has been enabled:
```
$ ./vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_1f1e372d    per-token private secret storage
ethereum/     ethsign      ethsign_d9f104c7      Ethereum Wallet
identity/     identity     identity_382e2000     identity store
secret/       kv           kv_32f5a684           key/value secret storage
sys/          system       system_21e0c7c7       system endpoints used for control, policy and debugging
```

### Enabling on a non-dev mode server
Setting up a non-dev mode server is beyond the scope of this README, as this is a very sensitive IT operation. But a simple procedure can be found in [the wiki page](https://github.com/kaleido-io/vault-plugin-secrets-ethsign/wiki/Setting-Up-A-Local-HashiCorp-Vault-Server).

Before enabling the plugin on the server, it must first be registered.

First copy the binary to the plugin folder for the server (consult the configuration file for the plugin folder location). Then calculate a SHA256 hash for the binary.
```
shasum -a 256 ./ethsign
```

Use the hash to register the plugin with vault:
```
 ./vault write sys/plugins/catalog/eth-hsm sha_256=$SHA command="ethsign"
```
> If the target vault server is enabled for TLS, and is using a self-signed certificate or other non-verifiable TLS certificate, then the command value needs to contain the switch to turn off TLS verify: `command="ethsign -tls-skip-verify"`

Once registered, just like in dev mode, it's ready to be enabled as a secret engine:
```
 ./vault secrets enable -path=ethereum -description="Eth Signing Wallet" -plugin-name=ethsign plugin
```

## Interacting with the ethsign Plugin
The plugin does not interact with the target blockchain. It has very simple responsibilities: sign transactions for submission to an Ethereum blockchain.

### Creating A New Signing Account
Create a new Ethereum account in the vault by POSTing to the `/accounts` endpoint.

Using the REST API:
```
$ curl -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{}' http://localhost:8200/v1/ethereum/accounts |jq

{
  "request_id": "a183425c-0998-0888-c768-8dda4ff60bef",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "address": "0xb579cbf259a8d36b22f2799eeeae5f3553b11eb7"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

Using the command line:
```
$ vault write -force ethereum/accounts

Key        Value
---        -----
address    0x73b508a63af509a28fb034bf4742bb1a91fcbc4e
```

### Importing An Existing Private Key
You can also create a new signing account by importing from an existing private key. The private key is passed in as a hexidecimal string, without the '0x' prfix.

Using the REST API:
```
$ curl -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"privateKey":"ec85999367d32fbbe02dd600a2a44550b95274cc67d14375a9f0bce233f13ad2"}' http://localhost:8200/v1/ethereum/accounts |jq

{
  "request_id": "a183425c-0998-0888-c768-8dda4ff60bef",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "address": "0xd5bcc62d9b1087a5cfec116c24d6187dd40fdf8a"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

Using the command line:
```
$ vault write ethereum/accounts privateKey=ec85999367d32fbbe02dd600a2a44550b95274cc67d14375a9f0bce233f13ad2

Key        Value
---        -----
address    0xd5bcc62d9b1087a5cfec116c24d6187dd40fdf8a
```

### List Existing Accounts
The list command only returns the addresses of the signing accounts. To return the private keys, use the `/export/accounts/:address` endpoint.

Using the REST API:
```
$  curl -H "Authorization: Bearer $TOKEN" http://localhost:8200/v1/ethereum/accounts?list=true |jq

{
  "request_id": "56c31ef5-9757-1ff4-354e-3b18ecd8ea77",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "keys": [
      "0xb579cbf259a8d36b22f2799eeeae5f3553b11eb7",
      "0x54edadf1696986c1884534bc6b633ff9a7fdb747"
    ]
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

Using the command line:
```
g$ vault list eth/accounts

Keys
----
0x73b508a63af509a28fb034bf4742bb1a91fcbc4e
0xd5bcc62d9b1087a5cfec116c24d6187dd40fdf8a
```

### Reading Individual Accounts
Inspect the key using the address. Only the address of the signing account is returned. To return the private key, use the `/export/accounts/:address` endpoint.

Using the REST API:
```
$  curl -H "Authorization: Bearer $TOKEN" http://localhost:8200/v1/ethereum/accounts/0x54edadf1696986c1884534bc6b633ff9a7fdb747 |jq

{
  "request_id": "a183425c-0998-0888-c768-8dda4ff60bef",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "address": "0xb579cbf259a8d36b22f2799eeeae5f3553b11eb7",
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

Using the command line:
```
$ vault read eth/accounts/0xd5bcc62d9b1087a5cfec116c24d6187dd40fdf8a

Key        Value
---        -----
address    0xd5bcc62d9b1087a5cfec116c24d6187dd40fdf8a
```

### Export An Account
You can also export the account by returning the private key.

Using the REST API:
```
$  curl -H "Authorization: Bearer $TOKEN" http://localhost:8200/v1/ethereum/export/accounts/0x54edadf1696986c1884534bc6b633ff9a7fdb747 |jq

{
  "request_id": "a183425c-0998-0888-c768-8dda4ff60bef",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "address": "0xb579cbf259a8d36b22f2799eeeae5f3553b11eb7",
    "privateKey": "ec85999367d32fbbe02dd600a2a44550b95274cc67d14375a9f0bce233f13ad2"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

Using the command line:
```
$ vault read eth/export/accounts/0xd5bcc62d9b1087a5cfec116c24d6187dd40fdf8a

Key           Value
---           -----
address       0xd5bcc62d9b1087a5cfec116c24d6187dd40fdf8a
privateKey    ec85999367d32fbbe02dd600a2a44550b95274cc67d14375a9f0bce233f13ad2
```

### Sign A Transaction
Use one of the accounts to sign a transaction.

Using the REST API:
```
$  curl -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" http://localhost:8200/v1/ethereum/accounts/0xc9389f98b1c5f5f9b6b61b5e3769471d550ad596/sign -d '{"data":"0x60fe47b10000000000000000000000000000000000000000000000000000000000000014","gas":30791,"gasPrice":0,"nonce":"0x0","to":"0xca0fe7354981aeb9d051e2f709055eb50b774087"}' |jq

{
  "request_id": "4b68c813-eda9-e3c7-4651-e9dbc526bf47",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "signed_transaction": "0xf888808083015f9094b401069f06a24155774bf8a0f6654ea299c8f68780a460fe47b10000000000000000000000000000000000000000000000000000000000000014840ea23e3fa088f4f5505f6f1da6c9a543863d5c7537e0dfc58618dbf34517c80875283d1e07a0583ecdc23ba3333a3f25611fffe0ec7fb585e9b9af93941f6e3ef8c8ef410698",
    "transaction_hash": "0x7ac47960a9398ae73b994c46fcb8834068195a2d3468c40a1eaad7ed4a15e68e"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

To sign a contract deploy, simply skip the `to` parameter in the JSON payload.

To use EIP155 signer, instead of Homestead signer, pass in `chainId` in the JSON payload.

The `signed_transaction` value in the response is already RLP encoded and can be submitted to an Ethereum blockchain directly.

## Access Policies
The plugin's endpoint paths are designed such that admin-level access policies vs. user-level access policies can be easily separated.

### Sample User Level Policy:
Use the following policy to assign to a regular user level access token, with the abilities to list keys, read individual keys and sign transactions.

```
/*
 * Ability to list existing keys ("list")
 */
path "ethereum/accounts" {
  capabilities = ["list"]
}
/*
 * Ability to retrieve individual keys ("read"), sign transactions ("create")
 */
path "ethereum/accounts/*" {
  capabilities = ["create", "read"]
}
```

### Sample Admin Level Policy:
Use the following policy to assign to a admin level access token, with the full ability to create keys, import existing private keys, export private keys, read/delete individual keys, and sign transactions.

```
/*
 * Ability to create key ("update") and list existing keys ("list")
 */
path "ethereum/accounts" {
  capabilities = ["update", "list"]
}
/*
 * Ability to retrieve individual keys ("read"), sign transactions ("create") and delete keys ("delete")
 */
path "ethereum/accounts/*" {
  capabilities = ["create", "read", "delete"]
}
/*
 * Ability to export private keys ("read")
 */
path "ethereum/export/accounts/*" {
  capabilities = ["read"]
}
```
