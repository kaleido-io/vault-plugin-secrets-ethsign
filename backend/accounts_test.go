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
  "context"
  "reflect"
  "testing"
  "time"

  log "github.com/hashicorp/go-hclog"
  "github.com/hashicorp/vault/sdk/helper/logging"
  "github.com/hashicorp/vault/sdk/logical"
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

func TestAccounts(t *testing.T) {
  b, _ := getBackend(t)

  // create key1
  req := logical.TestRequest(t, logical.CreateOperation, "accounts/key1")
  storage := req.Storage
  if _, err := b.HandleRequest(context.Background(), req); err != nil {
    t.Fatalf("err: %v", err)
  }

  // create key2
  req = logical.TestRequest(t, logical.CreateOperation, "accounts/key2")
  req.Storage = storage
  if _, err := b.HandleRequest(context.Background(), req); err != nil {
    t.Fatalf("err: %v", err)
  }

  req = logical.TestRequest(t, logical.ListOperation, "accounts")
  req.Storage = storage
  resp, err := b.HandleRequest(context.Background(), req)
  if err != nil {
    t.Fatalf("err: %v", err)
  }

  expected := &logical.Response{
    Data: map[string]interface{}{
      "keys": []string{"key1", "key2"},
    },
  }

  if !reflect.DeepEqual(resp, expected) {
    t.Fatalf("bad response.\n\nexpected: %#v\n\nGot: %#v", expected, resp)
  }

  // delete key2
  req = logical.TestRequest(t, logical.DeleteOperation, "accounts/key2")
  req.Storage = storage
  if _, err := b.HandleRequest(context.Background(), req); err != nil {
    t.Fatalf("err: %v", err)
  }

  expected = &logical.Response{
    Data: map[string]interface{}{
      "keys": []string{"key1"},
    },
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

