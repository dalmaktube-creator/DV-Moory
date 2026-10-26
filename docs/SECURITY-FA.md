# مدل امنیتی

- سرور فقط روی `127.0.0.1:8787` گوش می‌دهد.
- Caddy تنها مسیر HTTPS عمومی است و Bearer authentication را اعمال می‌کند.
- GitHub App فقط روی Repositoryهای انتخابی نصب می‌شود.
- Installation Token کوتاه‌مدت است و هرگز Log نمی‌شود.
- هر پروژه Deploy Key مستقل دارد.
- Force Push، Reset Hard، حذف Repository، حذف Release، API دلخواه و Shell دلخواه وجود ندارد.
- عملیات حساس به عبارت تأیید دقیق نیاز دارند.
- ورودی‌ها، Patchها، مسیر فایل و متن‌های GitHub برای Secret بررسی می‌شوند.
- سرویس با کاربر محدود، Resource limit و Filesystem hardening اجرا می‌شود.

## چرخش اعتبارنامه

در صورت احتمال افشا:

1. Bearer Token را تعویض کنید.
2. GitHub App private key قبلی را Revoke و کلید جدید ایجاد کنید.
3. Deploy Keyهای هر Repository را تعویض کنید.
4. Audit log و Security log گیت‌هاب را بررسی کنید.
