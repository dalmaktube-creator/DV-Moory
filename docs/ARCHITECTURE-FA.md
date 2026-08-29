# معماری

```text
Notion AI
  -> HTTPS + Bearer / Caddy
    -> MCP Server on 127.0.0.1
      -> Restricted Git CLI adapter
      -> Curated GitHub App API adapter
        -> Approved repositories only
```

Git CLI برای فایل، Patch، Commit و Push استفاده می‌شود. GitHub App API برای Issues، PR، Review، Actions و Releases استفاده می‌شود. این دو مسیر جدا هستند و هر دو allowlist و Audit دارند.
