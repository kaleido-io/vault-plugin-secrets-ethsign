package backend

import (
  "github.com/hashicorp/vault/sdk/framework"
  "github.com/hashicorp/vault/sdk/logical"
)

func pathSign(b *backend) *framework.Path {
  return &framework.Path{
    Pattern:      "accounts/" + framework.GenericNameRegex("name") + "/sign",
    HelpSynopsis: "Sign a provided transaction object.",
    HelpDescription: `

    Sign a transaction object with properties conforming to the Ethereum JSON-RPC documentation.

    `,
    Fields: map[string]*framework.FieldSchema{
      "name": &framework.FieldSchema{Type: framework.TypeString},
      "to": &framework.FieldSchema{
        Type:        framework.TypeString,
        Description: "(optional when creating new contract) The contract address the transaction is directed to.",
        Default:     "",
      },
      "data": &framework.FieldSchema{
        Type:        framework.TypeString,
        Description: "The compiled code of a contract OR the hash of the invoked method signature and encoded parameters.",
      },
      "input": &framework.FieldSchema{
        Type:        framework.TypeString,
        Description: "The compiled code of a contract OR the hash of the invoked method signature and encoded parameters.",
      },
      "value": &framework.FieldSchema{
        Type:        framework.TypeString,
        Description: "(optional) Integer of the value sent with this transaction (in wei).",
      },
      "nonce": &framework.FieldSchema{
        Type:        framework.TypeString,
        Description: "The transaction nonce.",
      },
      "gas": &framework.FieldSchema{
        Type:        framework.TypeString,
        Description: "(optional, default: 90000) Integer of the gas provided for the transaction execution. It will return unused gas",
        Default:     "90000",
      },
      "gasPrice": &framework.FieldSchema{
        Type:        framework.TypeString,
        Description: "(optional, default: 0) The gas price for the transaction in wei.",
        Default:     "0",
      },
      "chainId": &framework.FieldSchema{
        Type:        framework.TypeString,
        Description: "(optional) Chain ID of the target blockchain network. If present, EIP155 signer will be used to sign. If omitted, Homestead signer will be used.",
        Default:     "0",
      },
    },
    ExistenceCheck: b.pathExistenceCheck,
    Callbacks: map[logical.Operation]framework.OperationFunc{
      logical.CreateOperation: b.signTx,
    },
  }
}