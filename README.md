# LKM-SDK

package manager for the Dere3046 LKM ecosystem. the registry maps
every lib to its repo and a recommended rev, modules deploy deps
through the sdk CLI instead of hand vendoring.

## layout

- libs.lst       registry: name, git url, recommended rev, purpose
- scripts/sdk    CLI: ls, add, update, install
- scripts/deploy-deps.sh   core: closure resolve, clone, verify
- scripts/sync.sh          clone all libs into libs/ (gitignored)

## module usage

```sh
scripts/fetch-deps.sh    # clone SDK at .sdk-version, deploy deps
.sdk/scripts/sdk ls      # list registry
.sdk/scripts/sdk add HooKern        # add by recommended rev
.sdk/scripts/sdk update KallRecon   # bump to recommended rev
.sdk/scripts/sdk install            # deploy deps.lst, closure auto
```

module deps.lst holds only name and rev, urls come from the registry.
the module pins the SDK rev in .sdk-version, deployments reproduce.

## add a lib to the registry

the lib repo carries its own deps.mk metadata, append one line to
libs.lst and bump the recommended revs, modules pick it up with
sdk update.
