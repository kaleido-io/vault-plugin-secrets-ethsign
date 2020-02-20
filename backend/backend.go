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
  "fmt"

  "github.com/hashicorp/vault/sdk/framework"
  "github.com/hashicorp/vault/sdk/logical"
)

// Main function for the plugin extension
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
  b := newBackend(conf)
  if err := b.Setup(ctx, conf); err != nil {
    return nil, err
  }
  return b, nil
}

func newBackend(conf *logical.BackendConfig) *backend {
  var b backend
  b.Backend = &framework.Backend{
    BackendType: logical.TypeLogical,
    Paths: framework.PathAppend(
      accountsPaths(&b),
    ),
    PathsSpecial: &logical.Paths{
      SealWrapStorage: []string{
        "accounts/",
      },
    },
    Secrets:     []*framework.Secret{},
  }
  return &b
}

type backend struct {
  *framework.Backend
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
  out, err := req.Storage.Get(ctx, req.Path)
  if err != nil {
    return false, fmt.Errorf("Path existence check failed: %v", err)
  }

  return out != nil, nil
}