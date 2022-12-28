#!/usr/bin/bash -xeu
rm -rf docs
go run -modfile tools.mod github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name dinker --rendered-provider-name "Dinker" --rendered-website-dir docs
