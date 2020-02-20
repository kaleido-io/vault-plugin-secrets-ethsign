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

package main

import (
  "os"

  "github.com/hashicorp/go-hclog"
  "github.com/hashicorp/vault/api"
  "github.com/hashicorp/vault/sdk/plugin"
  "github.com/kaleido-io/eth-hsm/backend"
)

func main() {
  pluginMeta := &api.PluginAPIClientMeta{}
  flags := pluginMeta.FlagSet()
  flags.Parse(os.Args[1:])

  tlsConfig := pluginMeta.GetTLSConfig()
  tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

  err := plugin.Serve(&plugin.ServeOpts{
    BackendFactoryFunc: backend.Factory,
    TLSProviderFunc:    tlsProviderFunc,
  })
  if err != nil {
    logger := hclog.New(&hclog.LoggerOptions{})

    logger.Error("Eth-HSM plugin failed during startup, shutting down.", "error", err)
    os.Exit(1)
  }
}