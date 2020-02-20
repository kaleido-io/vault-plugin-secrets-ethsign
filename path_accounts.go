// Copyright © 2018 Immutability, LLC
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

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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

const (
	// InvalidAddress intends to prevent empty address_to
	InvalidAddress string = "InvalidAddress"
)

// Account is an Ethereum account
type Account struct {
	Address            string   `json:"address"` // Ethereum account address derived from the private key
	PrivateKey         string   `json:"private_key"`
	PublicKey          string   `json:"public_key"` // Ethereum public key derived from the private key
}

func accountsPaths(b *EthereumBackend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "accounts/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathAccountsList,
			},
			HelpSynopsis: "List all the Ethereum accounts at a path",
			HelpDescription: `
			All the Ethereum accounts will be listed.
			`,
		},
		&framework.Path{
			Pattern:      "accounts/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Create an Ethereum account using a generated or provided passphrase",
			HelpDescription: `

Creates (or updates) an Ethereum externally owned account (EOAs): an account controlled by a private key. Also
creates a geth compatible keystore that is protected by a passphrase that can be supplied or optionally
generated. The generator produces a high-entropy passphrase with the provided length and requirements.
The passphrase is not returned, but it is stored at a separate path (accounts/<name>/passphrase) to allow fine
grained access controls over exposure of the passphrase. The update operation will create a new keystore using
the new passphrase.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathAccountsRead,
				logical.CreateOperation: b.pathAccountsCreate,
				logical.DeleteOperation: b.pathAccountsDelete,
			},
		},
		&framework.Path{
			Pattern:      "accounts/" + framework.GenericNameRegex("name") + "/sign-tx",
			HelpSynopsis: "Sign a provided transaction. ",
			HelpDescription: `

Send ETH from an account.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"address_to": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The address of the account to send ETH to.",
					Default:     InvalidAddress,
				},
				"data": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The data to sign.",
				},
				"encoding": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "utf8",
					Description: "The encoding of the data to sign.",
				},
				"amount": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Amount of ETH (in wei).",
				},
				"nonce": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The transaction nonce.",
				},
				"gas_limit": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The gas limit for the transaction - defaults to 21000.",
					Default:     "21000",
				},
				"gas_price": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The gas price for the transaction in wei.",
					Default:     "0",
				},
				"send": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Description: "Send the transaction to the network.",
					Default:     true,
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathSignTx,
				logical.UpdateOperation: b.pathSignTx,
			},
		},
	}
}

func (b *EthereumBackend) pathAccountsList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *EthereumBackend) pathAccountsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	account, err := b.readAccount(ctx, req, name)
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

func (b *EthereumBackend) readAccount(ctx context.Context, req *logical.Request, name string) (*Account, error) {
	path := fmt.Sprintf("accounts/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var account Account
	err = entry.DecodeJSON(&account)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize account at %s", path)
	}

	return &account, nil
}

func (b *EthereumBackend) pathAccountsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	account, err := b.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("Error reading account")
	}
	if account == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address":              account.Address,
		},
	}, nil
}

func (b *EthereumBackend) pathAccountsCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	defer ZeroKey(privateKey)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyString := hexutil.Encode(privateKeyBytes)[2:]

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}

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
	entry, err := logical.StorageEntryJSON(req.Path, accountJSON)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address":              accountJSON.Address,
		},
	}, nil
}

func (b *EthereumBackend) pathSignTx(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var txDataToSign []byte
	name := data.Get("name").(string)
	dataOrFile := data.Get("data").(string)
	encoding := data.Get("encoding").(string)
	if encoding == "hex" {
		txDataToSign, _ = Decode([]byte(dataOrFile))
	} else if encoding == "utf8" {
		txDataToSign = []byte(dataOrFile)
	} else {
		return nil, fmt.Errorf("invalid encoding encountered - %s", encoding)
	}
	account, err := b.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading account")
	}
	if account == nil {
		return nil, nil
	}
	amount := ValidNumber(data.Get("amount").(string))
	if amount == nil {
		return nil, fmt.Errorf("invalid amount")
	}
	rawAddressTo, err := nonEmptyAddress("address_to", data.Get("address_to").(string))
	if err != nil {
		return nil, err
	}

	gasLimitIn := ValidNumber(data.Get("gas_limit").(string))
	if gasLimitIn == nil {
		return nil, fmt.Errorf("invalid gas limit")
	}
	gasLimit := gasLimitIn.Uint64()

	gasPrice := ValidNumber(data.Get("gas_price").(string))
	privateKey, err := crypto.HexToECDSA(account.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error reconstructing private key")
	}
	defer ZeroKey(privateKey)

	nonceIn := ValidNumber(data.Get("nonce").(string))
	var nonce uint64
	nonce = nonceIn.Uint64()

	toAddress := common.HexToAddress(rawAddressTo)
	tx := types.NewTransaction(nonce, toAddress, amount, gasLimit, gasPrice, txDataToSign)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(1)), privateKey)
	if err != nil {
		return nil, err
	}

	var signedTxBuff bytes.Buffer
	signedTx.EncodeRLP(&signedTxBuff)

	return &logical.Response{
		Data: map[string]interface{}{
			"transaction_hash":        signedTx.Hash().Hex(),
			"signed_transaction":      hexutil.Encode(signedTxBuff.Bytes()),
		},
	}, nil
}

func (b *EthereumBackend) pathContractsList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, req.Path)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
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

func nonEmptyAddress(name, rawAddress string) (string, error) {
	if rawAddress == InvalidAddress || rawAddress == "" {
		return "", fmt.Errorf("%s must be supplied", name)
	}
	return rawAddress, nil
}
