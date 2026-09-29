# YAML document parser

`tools/meow_yaml.js` is a browser-only bundle of the ISC-licensed
[yaml](https://eemeli.org/yaml/) document API. It retains comments, aliases and
unrelated configuration while LuCI edits its managed keys. The bundled file
and `meow_yaml.LICENSE` ship in the LuCI package; npm is not needed on OpenWrt.

Regenerate from pinned dependencies:

```sh
cd openwrt/luci-app-meow
npm ci
npm run build
```

The Settings map's save callback runs after LuCI parses form values and before
UCI is saved. YAML validation/upload failures reject that save. If UCI saving
subsequently fails, the callback's rollback restores the previous YAML unless
another writer has changed it. The separate Configuration editor applies the
same transformation before validating imported YAML.
