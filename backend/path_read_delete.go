package backend

import (
  "github.com/hashicorp/vault/sdk/framework"
  "github.com/hashicorp/vault/sdk/logical"
)

func pathReadAndDelete(b *backend) *framework.Path {
  return &framework.Path{
    Pattern:      "accounts/" + framework.GenericNameRegex("name"),
    HelpSynopsis: "Create, get or delete an Ethereum account by name",
    HelpDescription: `

    POST - create a new account for the given name
    GET - return the account by the name
    DELETE - deletes the account by the name

    `,
    Fields: map[string]*framework.FieldSchema{
      "name": &framework.FieldSchema{Type: framework.TypeString},
    },
    ExistenceCheck: b.pathExistenceCheck,
    Callbacks: map[logical.Operation]framework.OperationFunc{
      logical.ReadOperation:    b.readAccount,
      logical.DeleteOperation:  b.deleteAccount,
    },
  }
}
