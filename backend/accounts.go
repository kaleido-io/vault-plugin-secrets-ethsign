// Copyright © 2020 Kaleido
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backend

import (
  "bytes"
  "context"
  "crypto/ecdsa"
  "encoding/hex"
  "fmt"
  "math/big"
  "regexp"

  "github.com/ethereum/go-ethereum/common"
  "github.com/ethereum/go-ethereum/common/hexutil"
  "github.com/ethereum/go-ethereum/common/math"
  "github.com/ethereum/go-ethereum/core/types"
  "github.com/ethereum/go-ethereum/crypto"
  "github.com/hashicorp/vault/sdk/framework"
  "github.com/hashicorp/vault/sdk/logical"
  "golang.org/x/crypto/sha3"
)

type Account struct {
  Address     string  `json:"address"`
  PrivateKey  string  `json:"private_key"`
  PublicKey   string  `json:"public_key"`
}

func accountsPaths(b *backend) []*framework.Path {
  return []*framework.Path{
    &framework.Path{
      Pattern: "accounts",
      Callbacks: map[logical.Operation]framework.OperationFunc{
        logical.ListOperation: b.listAccounts,
        logical.CreateOperation: b.createAccount,
      },
      HelpSynopsis: "List all the Ethereum accounts maintained by the plugin backend, or create a new account.",
      HelpDescription: `

      GET - list all accounts
      POST - create a new account, the new account's address will be returned in the response

      `,
    },
    &framework.Path{
      Pattern:      "accounts/" + framework.GenericNameRegex("name"),
      HelpSynopsis: "Get or delete an Ethereum account by address",
      HelpDescription: `

      GET - return the account at the address
      DELETE - deletes the account at the address

      `,
      Fields: map[string]*framework.FieldSchema{
        "address": &framework.FieldSchema{Type: framework.TypeString},
      },
      ExistenceCheck: b.pathExistenceCheck,
      Callbacks: map[logical.Operation]framework.OperationFunc{
        logical.ReadOperation:   b.listAccounts,
        logical.DeleteOperation: b.deleteAccount,
      },
    },
    &framework.Path{
      Pattern:      "accounts/" + framework.GenericNameRegex("address") + "/sign",
      HelpSynopsis: "Sign a provided transaction object. ",
      HelpDescription: `

      Sign a transaction object with properties conforming to the Ethereum JSON-RPC documentation.

      `,
      Fields: map[string]*framework.FieldSchema{
        "from": &framework.FieldSchema{Type: framework.TypeString},
        "to": &framework.FieldSchema{
          Type:        framework.TypeString,
          Description: "(optional when creating new contract) The contract address the transaction is directed to.",
          Default:     "",
        },
        "data": &framework.FieldSchema{
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
    },
  }
}

func (b *backend) listAccounts(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
  vals, err := req.Storage.List(ctx, "accounts/")
  if err != nil {
    return nil, err
  }
  return logical.ListResponse(vals), nil
}

func (b *backend) createAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
  privateKey, err := crypto.GenerateKey()
  if err != nil {
    return nil, err
  }
  defer ZeroKey(privateKey)
  privateKeyBytes := crypto.FromECDSA(privateKey)
  privateKeyString := hexutil.Encode(privateKeyBytes)[2:]

  publicKey := privateKey.Public()
  publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
  publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
  publicKeyString := hexutil.Encode(publicKeyBytes)[4:]

  hash := sha3.NewLegacyKeccak256()
  hash.Write(publicKeyBytes[1:])
  address := hexutil.Encode(hash.Sum(nil)[12:])

  accountJSON := &Account{
    Address:            address,
    PrivateKey:         privateKeyString,
    PublicKey:          publicKeyString,
  }
  // the account is assigned to path "/accounts/0x1234...." using the account's address
  accountPath := fmt.Sprintf("accounts/%s", address)
  entry, err := logical.StorageEntryJSON(accountPath, accountJSON)
  if err != nil {
    return nil, err
  }

  err = req.Storage.Put(ctx, entry)
  if err != nil {
    return nil, err
  }

  return &logical.Response{
    Data: map[string]interface{}{
      "address": accountJSON.Address,
    },
  }, nil
}

func (b *backend) readAccount(ctx context.Context, req *logical.Request, address string) (*Account, error) {
  path := fmt.Sprintf("accounts/%s", address)
  entry, err := req.Storage.Get(ctx, path)
  if err != nil {
    return nil, err
  }
  if entry == nil {
    return nil, nil
  }

  var account Account
  err = entry.DecodeJSON(&account)

  if account.Address == "" {
    return nil, fmt.Errorf("Failed to deserialize account at %s", path)
  }

  return &account, nil
}

func (b *backend) deleteAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
  address := data.Get("address").(string)
  account, err := b.readAccount(ctx, req, address)
  if err != nil {
    return nil, fmt.Errorf("Error reading account")
  }
  if account == nil {
    return nil, nil
  }
  if err := req.Storage.Delete(ctx, req.Path); err != nil {
    return nil, err
  }
  return nil, nil
}

func (b *backend) signTx(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
  from := data.Get("from").(string)

  var txDataToSign []byte
  dataOrFile := data.Get("data").(string)
  txDataToSign, err := Decode([]byte(dataOrFile))
  if err != nil {
    return nil, err
  }

  account, err := b.readAccount(ctx, req, from)
  if err != nil {
    return nil, fmt.Errorf("Error retrieving signing account %s", from)
  }
  if account == nil {
    return nil, nil
  }
  amount := ValidNumber(data.Get("value").(string))
  if amount == nil {
    return nil, fmt.Errorf("Invalid amount for the 'value' field")
  }

  rawAddressTo := data.Get("to").(string)

  chainId := ValidNumber(data.Get("chainId").(string))
  if chainId == nil {
    return nil, fmt.Errorf("Invalid 'chainId' value")
  }

  gasLimitIn := ValidNumber(data.Get("gas").(string))
  if gasLimitIn == nil {
    return nil, fmt.Errorf("Invalid gas limit")
  }
  gasLimit := gasLimitIn.Uint64()

  gasPrice := ValidNumber(data.Get("gasPrice").(string))

  privateKey, err := crypto.HexToECDSA(account.PrivateKey)
  if err != nil {
    return nil, fmt.Errorf("Error reconstructing private key from retrieved hex")
  }
  defer ZeroKey(privateKey)

  nonceIn := ValidNumber(data.Get("nonce").(string))
  var nonce uint64
  nonce = nonceIn.Uint64()

  toAddress := common.HexToAddress(rawAddressTo)
  tx := types.NewTransaction(nonce, toAddress, amount, gasLimit, gasPrice, txDataToSign)
  var signer types.Signer
  if big.NewInt(0).Cmp(chainId) == 0 {
    signer = types.HomesteadSigner{}
  } else {
    signer = types.NewEIP155Signer(chainId)
  }
  signedTx, err := types.SignTx(tx, signer, privateKey)
  if err != nil {
    return nil, err
  }

  var signedTxBuff bytes.Buffer
  signedTx.EncodeRLP(&signedTxBuff)

  return &logical.Response{
    Data: map[string]interface{}{
      "transaction_hash":   signedTx.Hash().Hex(),
      "signed_transaction": hexutil.Encode(signedTxBuff.Bytes()),
    },
  }, nil
}

// ZeroKey clears the memory allocated for the private key
func ZeroKey(k *ecdsa.PrivateKey) {
  b := k.D.Bits()
  for i := range b {
    b[i] = 0
  }
}

func Decode(src []byte) ([]byte, error) {
  raw := make([]byte, hex.EncodedLen(len(src)))
  n, err := hex.Decode(raw, src)
  if err != nil {
    return nil, err
  }
  raw = raw[:n]
  return raw[:], nil
}

func ValidNumber(input string) *big.Int {
  if input == "" {
    return big.NewInt(0)
  }
  matched, err := regexp.MatchString("([0-9])", input)
  if !matched || err != nil {
    return nil
  }
  amount := math.MustParseBig256(input)
  return amount.Abs(amount)
}
