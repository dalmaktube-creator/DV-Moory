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

## هستهٔ Worker

- Agent مسئول استدلال، تصمیم و بازبینی است؛ Moory فقط کار قطعی و مکانیکی را اجرا می‌کند.
- سطح `summary` برای شروع، `evidence` پیش از ویرایش و `full` فقط به‌عنوان مسیر فرار از کمبود شواهد استفاده می‌شود.
- نقشهٔ مخزن بر اساس SHA کش می‌شود، اما وضعیت worktree همیشه زنده خوانده می‌شود.
- `apply_change_set` فقط تغییر فایل‌های tracked را تراکنشی اعمال می‌کند و در شکست اعتبارسنجی rollback انجام می‌دهد.
- Buildهای سنگین و ماتریسی در GitHub Actions باقی می‌مانند.
- `release_readiness` پیش از انتشار، وضعیت شاخه، CI، changelog و tag را بدون تغییر مخزن بررسی می‌کند.
