# نصب آسان Moory روی Ubuntu

## روش پیشنهادی

برای نصب روی یک سرور تازه با Ubuntu 24.04 فقط یک فرمان لازم است:

```bash
curl -fsSL https://raw.githubusercontent.com/dalmaktube-creator/DV-Moory/main/install.sh | sudo bash
```

نصاب رنگی وابستگی‌ها، کاربر محدود، Python، سرویس systemd، Caddy و ابزار مدیریتی را آماده می‌کند. پس از نصب، تمام مدیریت‌های روزمره از منوی زیر انجام می‌شوند:

```bash
sudo moory
```

## انتخاب روش اتصال GitHub

نصاب دو گزینه توضیح‌دار نمایش می‌دهد:

1. **Quick Mode:** با Fine-grained GitHub Token؛ مناسب استفاده شخصی و سریع.
2. **Hardened Mode:** با GitHub App و Tokenهای کوتاه‌مدت؛ مناسب Production و تیم‌ها.

Secretها هنگام ورود مخفی هستند و با دسترسی محدود روی سرور ذخیره می‌شوند.

## افزودن Repository بدون نوشتن دستور

در منوی `moory` گزینه **Add repository** را انتخاب کنید. Moory:

1. نام کوتاه، `owner/repository` و Branch مجاز را می‌پرسد.
2. Deploy Key اختصاصی تولید می‌کند.
3. فقط Public Key را برای قراردادن در GitHub نمایش می‌دهد.
4. پس از تأیید کاربر، SSH را آزمایش می‌کند.
5. Repository را Clone می‌کند.
6. Registry را به‌روزرسانی و MCP را Restart می‌کند.

کلید خصوصی هیچ‌گاه نمایش داده نمی‌شود.

## منوی مدیریت

منو شامل Status، افزودن/فهرست/حذف Repository، تنظیم GitHub، اطلاعات اتصال Notion، Logها، Backup، Rotate Token، Restart و Update است.

## مراحل دستی اجتناب‌ناپذیر

- ساخت Fine-grained Token یا GitHub App در حساب GitHub
- انتخاب Repositoryهای مجاز
- افزودن Public Deploy Key به Repository
- اشاره DNS به VPS در حالت Domain اختصاصی
- افزودن URL و Bearer Token نهایی به Custom MCP در Notion

## اتصال ChatGPT با OAuth

برای اتصال Custom MCP در ChatGPT بدون کپی‌کردن Bearer Token:

1. ابتدا دامنه HTTPS عمومی را در `moory-setup` تنظیم کنید.
2. یک GitHub OAuth App بسازید.
3. Callback URL را دقیقاً روی آدرس زیر بگذارید:
   `https://DOMAIN/oauth/github/callback`
4. در مرحله `CHATGPT / MCP OAUTH` مقدار Client ID و Client Secret را وارد
   کنید و نام کاربری مجاز GitHub را در allowlist بگذارید.
5. در ChatGPT آدرس `https://DOMAIN/mcp` را وارد کنید و روش Authentication را
   روی OAuth بگذارید.

در این حالت Moory metadataهای استاندارد MCP Authorization، ثبت پویای client،
Authorization Code + PKCE و tokenهای کوتاه‌مدت را ارائه می‌کند. GitHub فقط برای
تشخیص هویت کاربر استفاده می‌شود و token آن روی دیسک ذخیره نمی‌شود.

Moory برای این مراحل توضیح، مقدار لازم و توقف برای تأیید را داخل Wizard نمایش می‌دهد.

## مسیرهای اصلی

- برنامه: `/srv/moory/app/server.py`
- محیط Python: `/srv/moory/venv`
- تنظیمات: `/srv/moory/config`
- Repositoryها: `/srv/moory/repos`
- Audit log: `/srv/moory/logs/audit.jsonl`
- SSH: `/srv/moory/.ssh`
- سورس قابل Update: `/opt/moory`
