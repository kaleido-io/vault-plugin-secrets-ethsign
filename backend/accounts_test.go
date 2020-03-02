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
  "errors"
  "math/big"
  "reflect"
  "strings"
  "testing"
  "time"

  "github.com/ethereum/go-ethereum/common/hexutil"
  "github.com/ethereum/go-ethereum/core/types"
  "github.com/ethereum/go-ethereum/rlp"

  log "github.com/hashicorp/go-hclog"
  "github.com/hashicorp/vault/sdk/helper/logging"
  "github.com/hashicorp/vault/sdk/logical"

  "github.com/stretchr/testify/assert"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
  config := &logical.BackendConfig{
    Logger:      logging.NewVaultLogger(log.Trace),
    System:      &logical.StaticSystemView{},
    StorageView: &logical.InmemStorage{},
    BackendUUID: "test",
  }

  b, err := Factory(context.Background(), config)
  if err != nil {
    t.Fatalf("unable to create backend: %v", err)
  }

  // Wait for the upgrade to finish
  time.Sleep(time.Second)

  return b, config.StorageView
}

type StorageMock struct {
  switches []int
}
func (s StorageMock) List(c context.Context, path string) ([]string, error) {
  if s.switches[0] == 1 {
    return []string{"key1", "key2"}, nil
  } else {
    return nil, errors.New("Bang for List!")
  }
}
func (s StorageMock) Get(c context.Context, path string) (*logical.StorageEntry, error) {
  if s.switches[1] == 2 {
    var entry logical.StorageEntry
    return &entry, nil
  } else if s.switches[1] == 1 {
    return nil, nil
  } else {
    return nil, errors.New("Bang for Get!")
  }
}
func (s StorageMock) Put(c context.Context, se *logical.StorageEntry) error {
  if s.switches[2] == 1 {
    if se.Key[:8] == "mappings" {
      return errors.New("Bang for Put mappings!")
    } else {
      return nil
    }
  }
  return errors.New("Bang for Put!")
}  
func (s StorageMock) Delete(c context.Context, path string) error {
  return errors.New("Bang for Delete!")
}

func newStorageMock() StorageMock {
  var sm StorageMock
  sm.switches = []int{0, 0, 0, 0}
  return sm
}

func TestAccounts(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)

  // create key1
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/key1")
  storage := req.Storage
  res, err := b.HandleRequest(context.Background(), req)
  if err != nil {
    t.Fatalf("err: %v", err)
  }

  address1 := res.Data["address"].(string)
  assert.Equal("key1", res.Data["name"])

  // create key2
  req = logical.TestRequest(t, logical.CreateOperation, "accounts/key2")
  req.Storage = storage
  res, err = b.HandleRequest(context.Background(), req)
  if err != nil {
    t.Fatalf("err: %v", err)
  }

  address2 := res.Data["address"].(string)
  assert.Equal("key2", res.Data["name"])

  req = logical.TestRequest(t, logical.ListOperation, "accounts")
  req.Storage = storage
  resp, err := b.HandleRequest(context.Background(), req)
  if err != nil {
    t.Fatalf("err: %v", err)
  }

  expected := &logical.Response{
    Data: map[string]interface{}{
      "keys": []string{address1, address2},
    },
  }

  if !reflect.DeepEqual(resp, expected) {
    t.Fatalf("bad response.\n\nexpected: %#v\n\nGot: %#v", expected, resp)
  }

  // read account by key name
  req = logical.TestRequest(t, logical.ReadOperation, "accounts/key1")
  req.Storage = storage
  resp, err = b.HandleRequest(context.Background(), req)
  if err != nil {
    t.Fatalf("err: %v", err)
  }
  expected = &logical.Response{
    Data: map[string]interface{}{
      "address": address1,
      "name": "key1",
    },
  }
  if !reflect.DeepEqual(resp, expected) {
    t.Fatalf("bad response.\n\nexpected: %#v\n\nGot: %#v", expected, resp)
  }

  // read account by address
  req = logical.TestRequest(t, logical.ReadOperation, "accounts/" + address1)
  req.Storage = storage
  resp, err = b.HandleRequest(context.Background(), req)
  if err != nil {
    t.Fatalf("err: %v", err)
  }
  if !reflect.DeepEqual(resp, expected) {
    t.Fatalf("bad response.\n\nexpected: %#v\n\nGot: %#v", expected, resp)
  }

  // read account by address without the "0x" prefix
  req = logical.TestRequest(t, logical.ReadOperation, "accounts/" + address1[2:])
  req.Storage = storage
  resp, err = b.HandleRequest(context.Background(), req)
  if err != nil {
    t.Fatalf("err: %v", err)
  }
  if !reflect.DeepEqual(resp, expected) {
    t.Fatalf("bad response.\n\nexpected: %#v\n\nGot: %#v", expected, resp)
  }

  // sign contract creation TX by address using Homestead signer
  dataToSign := "608060405234801561001057600080fd5b506040516020806101d783398101604052516000556101a3806100346000396000f3006080604052600436106100615763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416632a1afcd981146100665780632c46b2051461008d57806360fe47b1146100a25780636d4ce63c1461008d575b600080fd5b34801561007257600080fd5b5061007b6100ba565b60408051918252519081900360200190f35b34801561009957600080fd5b5061007b6100c0565b3480156100ae57600080fd5b5061007b6004356100c6565b60005481565b60005490565b60006064821061013757604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601960248201527f56616c75652063616e206e6f74206265206f7665722031303000000000000000604482015290519081900360640190fd5b60008290556040805183815290517f9455957c3b77d1d4ed071e2b469dd77e37fc5dfd3b4d44dc8a997cc97c7b3d499181900360200190a15050600054905600a165627a7a72305820a22d4674e519555e6f065ccf98b5bd479e108895cbddc10cba200c775d0008730029000000000000000000000000000000000000000000000000000000000000000a"
  req = logical.TestRequest(t, logical.CreateOperation, "accounts/" + address1 + "/sign")
  req.Storage = storage
  data := map[string]interface{}{
    "data": dataToSign,
    "gas": 500000,
    "nonce": "0x2",
    "gasPrice": 0,
  }
  req.Data = data
  resp, err = b.HandleRequest(context.Background(), req)
  if err != nil {
    t.Fatalf("err: %v", err)
  }
  signedTx := resp.Data["signed_transaction"].(string)
  signatureBytes, err := hexutil.Decode(signedTx)
  var tx types.Transaction
  err = tx.DecodeRLP(rlp.NewStream(bytes.NewReader(signatureBytes), 0))
  if err != nil {
    t.Fatalf("err: %v", err)
  }
  v, _, _ := tx.RawSignatureValues()
  assert.Equal(true, contains([]*big.Int{big.NewInt(27), big.NewInt(28)}, v))

  sender, _ := types.Sender(types.HomesteadSigner{}, &tx)
  assert.Equal(address1, strings.ToLower(sender.Hex()))

  // sign TX by address without "0x" using EIP155 signer
  dataToSign = "60fe47b10000000000000000000000000000000000000000000000000000000000000014"
  req = logical.TestRequest(t, logical.CreateOperation, "accounts/" + address2[2:] + "/sign")
  req.Storage = storage
  data = map[string]interface{}{
    "data": dataToSign,
    "to": "0xf809410b0d6f047c603deb311979cd413e025a84",
    "gas": 50000,
    "nonce": "0x3",
    "gasPrice": 0,
    "chainId": 12345,
  }
  req.Data = data
  resp, err = b.HandleRequest(context.Background(), req)
  if err != nil {
    t.Fatalf("err: %v", err)
  }
  signedTx = resp.Data["signed_transaction"].(string)
  signatureBytes, err = hexutil.Decode(signedTx)
  err = tx.DecodeRLP(rlp.NewStream(bytes.NewReader(signatureBytes), 0))
  if err != nil {
    t.Fatalf("err: %v", err)
  }
  v, _, _ = tx.RawSignatureValues()
  assert.Equal(true, contains([]*big.Int{big.NewInt(24725), big.NewInt(24726)}, v))

  sender, _ = types.Sender(types.HomesteadSigner{}, &tx)
  assert.Equal(address1, strings.ToLower(sender.Hex()))

  // delete key by name
  req = logical.TestRequest(t, logical.DeleteOperation, "accounts/key1")
  req.Storage = storage
  if _, err := b.HandleRequest(context.Background(), req); err != nil {
    t.Fatalf("err: %v", err)
  }

  expected = &logical.Response{
    Data: map[string]interface{}{},
  }

  // delete key by address
  req = logical.TestRequest(t, logical.DeleteOperation, "accounts/" + address2)
  req.Storage = storage
  if _, err := b.HandleRequest(context.Background(), req); err != nil {
    t.Fatalf("err: %v", err)
  }

  req = logical.TestRequest(t, logical.ListOperation, "accounts")
  req.Storage = storage
  resp, err = b.HandleRequest(context.Background(), req)
  if err != nil {
    t.Fatalf("err: %v", err)
  }

  if !reflect.DeepEqual(resp, expected) {
    t.Fatalf("bad response.\n\nexpected: %#v\n\nGot: %#v", expected, resp)
  }
}

func TestListAccountsFailure1(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.ListOperation, "accounts")
  sm := newStorageMock()
  req.Storage = sm
  _, err := b.HandleRequest(context.Background(), req)

  assert.Equal("Bang for List!", err.Error())
}

func TestListAccountsFailure2(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.ListOperation, "accounts")
  sm := newStorageMock()
  sm.switches[0] = 1 // have the List() method return success
  req.Storage = sm
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(err)
  assert.ElementsMatch([]string{"0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000"}, resp.Data["keys"])
}

func TestCreateAccountsFailure1(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/key1")
  sm := newStorageMock()
  req.Storage = sm
  _, err := b.HandleRequest(context.Background(), req)

  assert.Equal("Bang for Put!", err.Error())
}

func TestCreateAccountsFailure2(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/key1")
  sm := newStorageMock()
  sm.switches[2] = 1
  req.Storage = sm
  _, err := b.HandleRequest(context.Background(), req)

  assert.Equal("Bang for Put mappings!", err.Error())
}

func TestReadAccountsFailure1(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.ReadOperation, "accounts/key1")
  sm := newStorageMock()
  req.Storage = sm
  _, err := b.HandleRequest(context.Background(), req)

  assert.Equal("Bang for Get!", err.Error())
}

func TestReadAccountsFailure2(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.ReadOperation, "accounts/key1")
  sm := newStorageMock()
  sm.switches[1] = 1
  req.Storage = sm
  resp, _ := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
}

func TestReadAccountsFailure3(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.ReadOperation, "accounts/0xf809410b0d6f047c603deb311979cd413e025a84")
  sm := newStorageMock()
  req.Storage = sm
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Equal("Bang for Get!", err.Error())
}

func TestReadAccountsFailure4(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.ReadOperation, "accounts/0xf809410b0d6f047c603deb311979cd413e025a84")
  sm := newStorageMock()
  sm.switches[1] = 1
  req.Storage = sm
  resp, _ := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
}

func TestDeleteAccountsFailure1(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.DeleteOperation, "accounts/key1")
  sm := newStorageMock()
  req.Storage = sm
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Equal("Bang for Get!", err.Error())
}

func TestDeleteAccountsFailure2(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.DeleteOperation, "accounts/key1")
  sm := newStorageMock()
  sm.switches[1] = 1
  req.Storage = sm
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Nil(err)
}

func TestDeleteAccountsFailure3(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.DeleteOperation, "accounts/key1")
  sm := newStorageMock()
  sm.switches[1] = 2
  req.Storage = sm
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Equal("Bang for Delete!", err.Error())
}

func TestSignTxFailure1(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/0xf809410b0d6f047c603deb311979cd413e025a84/sign")
  sm := newStorageMock()
  req.Storage = sm
  req.Data["data"] = "0xabc"
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Equal("hex string of odd length", err.Error())
}

func TestSignTxFailure2(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/0xf809410b0d6f047c603deb311979cd413e025a84/sign")
  sm := newStorageMock()
  req.Storage = sm
  req.Data["data"] = "0xabcd"
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Equal("Error retrieving signing account 0xf809410b0d6f047c603deb311979cd413e025a84", err.Error())
}

func TestSignTxFailure3(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/0xf809410b0d6f047c603deb311979cd413e025a84/sign")
  sm := newStorageMock()
  sm.switches[1] = 1
  req.Storage = sm
  req.Data["data"] = "0xabcd"
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Equal("Signing account 0xf809410b0d6f047c603deb311979cd413e025a84 does not exist", err.Error())
}

func TestSignTxFailure4(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/0xf809410b0d6f047c603deb311979cd413e025a84/sign")
  sm := newStorageMock()
  sm.switches[1] = 2
  req.Storage = sm
  req.Data["data"] = "0xabcd"
  req.Data["value"] = "abcd"
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Equal("Invalid amount for the 'value' field", err.Error())
}

func TestSignTxFailure5(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/0xf809410b0d6f047c603deb311979cd413e025a84/sign")
  sm := newStorageMock()
  sm.switches[1] = 2
  req.Storage = sm
  req.Data["data"] = "0xabcd"
  req.Data["chainId"] = "abcd"
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Equal("Invalid 'chainId' value", err.Error())
}

func TestSignTxFailure6(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/0xf809410b0d6f047c603deb311979cd413e025a84/sign")
  sm := newStorageMock()
  sm.switches[1] = 2
  req.Storage = sm
  req.Data["data"] = "0xabcd"
  req.Data["gas"] = "abcd"
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Equal("Invalid gas limit", err.Error())
}

func TestSignTxFailure7(t *testing.T) {
  assert := assert.New(t)

  b, _ := getBackend(t)
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/0xf809410b0d6f047c603deb311979cd413e025a84/sign")
  sm := newStorageMock()
  sm.switches[1] = 2
  req.Storage = sm
  req.Data["data"] = "0xabcd"
  resp, err := b.HandleRequest(context.Background(), req)

  assert.Nil(resp)
  assert.Equal("Error reconstructing private key from retrieved hex", err.Error())
}

func contains(arr []*big.Int, value *big.Int) bool {
   for _, a := range arr {
      if a.Cmp(value) == 0 {
         return true
      }
   }
   return false
}

