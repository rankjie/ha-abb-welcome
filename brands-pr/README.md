# Brands PR assets

Home Assistant integrations don't bundle their own icon — icons are served from the
[`home-assistant/brands`](https://github.com/home-assistant/brands) repo. To make
this integration's icon appear in the HA "Devices & Services" page and in HACS,
submit a PR to that repo.

## Files in this folder

```
abb_welcome/icon.png       256×256 PNG, transparent background
abb_welcome/icon@2x.png    512×512 PNG, transparent background
```

`icon.png` is a stylised approximation of the ABB wordmark, generated with PIL
so the repo doesn't ship trademarked assets verbatim. Replace it with a higher
quality version any time before submitting the PR — the file paths and sizes
must stay the same.

## Submitting to home-assistant/brands

1. Fork <https://github.com/home-assistant/brands>.
2. Copy this folder into the fork at `custom_integrations/abb_welcome/`:
   ```
   custom_integrations/
     abb_welcome/
       icon.png
       icon@2x.png
   ```
3. Run their test suite locally if you can (`./script/test`) — it checks PNG
   sizes, transparency, and that no metadata is embedded.
4. Open a PR. The brands maintainers may ask for adjustments; iterate until
   merged.

Once merged, HA pulls the icons automatically — you don't need to release a new
version of this integration.
