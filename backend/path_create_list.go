package backend

import (
  "github.com/hashicorp/vault/sdk/framework"
  "github.com/hashicorp/vault/sdk/logical"
)

func pathCreateAndList(b *backend) *framework.Path {
  return &framework.Path{
    Pattern: "accounts/?",
    Callbacks: map[logical.Operation]framework.OperationFunc{
      logical.ListOperation:    b.listAccounts,
      logical.UpdateOperation:  b.createAccount,
    },
    HelpSynopsis: "List all the Ethereum accounts maintained by the plugin backend and create new accounts.",
    HelpDescription: `

    LIST - list all accounts
    POST - create a new account

    `,
  }
}