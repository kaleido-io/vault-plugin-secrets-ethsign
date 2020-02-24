# eth-hasm

[![Build Status](https://travis-ci.org/kaleido-io/eth-hsm.svg?branch=master)](https://travis-ci.org/kaleido-io/eth-hsm)
[![codecov](https://codecov.io/gh/kaleido-io/eth-hsm/branch/master/graph/badge.svg?token=3LlJ7aSeW2)](https://codecov.io/gh/kaleido-io/eth-hsm)

A HashiCorp Vault plugin that supports secp256k1 based signing, with an API interface that turns the vault into a software-based HSM device.

![Overview](/resources/eth-hsm.png)

The plugin only exposes the following endpoints to enable the client to generate signing keys for the secp256k1 curve suitable for signing Ethereum transactions, list existing signing keys by their names and addresses, and a `/sign` endpoint for each account. The generated private keys are saved in the vault as a secret. It never gives out the private keys.

## Build
These dependencies are needed:

* go 1.13

To build the binary:
```
make all
```

## Installing the Plugin on HashiCorp Vault server
The plugin must be registered and enabled on the vault server as a secret engine.

### Enabling on a dev mode server
The easiest way to try out the plugin is using a dev mode server to load it.

Download the binary: [https://www.vaultproject.io/downloads/](https://www.vaultproject.io/downloads/)

First copy it to the plugins folder, say `~/.vault.d/vault-plugins/`.
```
./vault server -dev -dev-plugin-dir=/Users/alice/.vault.d/vault_plugins/
```

The plugin should have already been registered in the system plugins catalog:
```
$ ./vault login <root token>
$ ./vault read sys/plugins/catalog
Key         Value
---         -----
auth        [alicloud app-id approle aws azure centrify cert cf gcp github jwt kubernetes ldap oci oidc okta pcf radius userpass]
database    [cassandra-database-plugin elasticsearch-database-plugin hana-database-plugin influxdb-database-plugin mongodb-database-plugin mssql-database-plugin mysql-aurora-database-plugin mysql-database-plugin mysql-legacy-database-plugin mysql-rds-database-plugin postgresql-database-plugin]
secret      [ad alicloud aws azure cassandra consul eth-hsm gcp gcpkms kv mongodb mssql mysql nomad pki postgresql rabbitmq ssh totp transit]
```

Note the `eth-hsm` entry in the secret section. Now it's ready to be enabled:
```
 ./vault secrets enable -path=ethereum -description="Eth HSM" -plugin-name=eth-hsm plugin
```

To verify the new secret engine based on the plugin has been enabled:
```
$ ./vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_1f1e372d    per-token private secret storage
ethereum/     eth-hsm      eth-hsm_d9f104c7      Eth HSM
identity/     identity     identity_382e2000     identity store
secret/       kv           kv_32f5a684           key/value secret storage
sys/          system       system_21e0c7c7       system endpoints used for control, policy and debugging
```

### Enabling on a non-dev mode server
Setting up a non-dev mode server is beyond the scope of this README, as this is a very sensitive IT operation. But a simple procedure can be found in [the wiki page](https://github.com/kaleido-io/eth-hsm/wiki/Setting-Up-A-Local-HashiCorp-Vault-Server).

Before enabling the plugin on the server, it must first be registered.

First copy the binary to the plugin folder for the server (consult the configuration file for the plugin folder location). Then calculate a SHA256 hash for the binary.
```
shasum -a 256 ./eth-hsm 
```

Use the hash to register the plugin with vault:
```
 ./vault write sys/plugins/catalog/eth-hsm sha_256=$SHA command="eth-hsm"
```

Once registered, just like in dev mode, it's ready to be enabled as a secret engine:
```
 ./vault secrets enable -path=ethereum -description="Eth HSM" -plugin-name=eth-hsm plugin
```

## Interacting with the eth-hsm Plugin
The plugin does not interact with the target blockchain. It has very simple responsibilities: sign transactions to submit to an Ethereum blockchain.

Create a new Ethereum account in the vault:
```
$ curl -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{}' http://localhost:8200/v1/ethereum/accounts/key1 |jq
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

List existing accounts:
```
$  curl -H "Authorization: Bearer $TOKEN" -X LIST http://localhost:8200/v1/ethereum/accounts/ |jq
{
  "request_id": "56c31ef5-9757-1ff4-354e-3b18ecd8ea77",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "keys": [
      "key1"
    ]
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

Inspect the key for the public address:
```
$  curl -H "Authorization: Bearer $TOKEN" http://localhost:8200/v1/ethereum/accounts/key1 |jq
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

Use one of the accounts to sign a transaction:
```
$  curl -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" http://localhost:8200/v1/ethereum/accounts/key1/sign -d '{"data":"0x60fe47b10000000000000000000000000000000000000000000000000000000000000014","gas":30791,"gasPrice":0,"nonce":"0x0","to":"0xca0fe7354981aeb9d051e2f709055eb50b774087"}' |jq
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
