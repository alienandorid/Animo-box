# ANIME BOX — Full-stack e-commerce starter

This is a full-stack custom store (not a Shopify theme). It includes a Bengali-first storefront, product search/categories, cart, COD checkout, server-side price/stock validation, real OTP provider integration, PostgreSQL order storage, and a protected admin dashboard.

## Important before using real customers

- This source code is prepared, but it is **not deployed** and no live URL exists yet.
- Real SMS cannot be sent until a provider account is approved and its credentials are added as server environment variables.
- The included OTP adapter uses **Banglalink W3 SMS OTP** (`/otp/request` and `/otp/verify`). W3 SMS's OTP service is a Banglalink network service, so it should not be treated as coverage for every Bangladesh operator. If you need OTP for GP, Robi, Airtel, Teletalk and Banglalink, choose an SMS/OTP provider that confirms multi-operator Bangladesh delivery and replace/extend the provider adapter.
- W3 SMS requires an approved `applicationId`, API password, and the backend's outbound IP to be provisioned. A host with changing outbound IPs may not work; confirm static outbound IP/allowlisting with the hosting provider before choosing a production host.
- Never put OTP credentials, database URLs, JWT secrets, or admin passwords in browser code or commit `.env` to a public repository.
- Do not use a free/ephemeral database for real orders. Use a persistent managed PostgreSQL database with backups.

## Features

### Storefront
- Responsive ANIME BOX home page and category navigation
- Search, category filtering, price sorting
- Product cards, stock visibility, cart quantity controls
- COD checkout with Bangladesh address fields
- OTP request and provider-side OTP verification before order creation
- Server recalculates product prices and checks inventory; browser prices are never trusted
- Free delivery for cart subtotal >= ৳3,000; otherwise ৳80 (change in `server.js`)

### Admin (`/admin`)
- Environment-provisioned admin account; no public admin registration
- HTTP-only, secure-in-production login cookie; bcrypt password hash; 8-hour JWT session
- Dashboard counts, order list, customer address and items
- Click-to-call customer link, OTP-verified indicator
- Update order status: pending, confirmed by phone, processing, shipped, delivered, cancelled
- Add/edit/hide products, change prices and stock

## Local setup

Requirements: Node.js 20+ and PostgreSQL.

1. Create a PostgreSQL database.
2. Copy `.env.example` to `.env` and fill in `DATABASE_URL`, a long random `JWT_SECRET`, `ADMIN_EMAIL`, and a strong `ADMIN_PASSWORD`.
3. For real OTP, create a W3 SMS account, obtain an API key, and set `W3SMS_API_KEY`, an approved `W3SMS_SENDER_ID`, and a unique 32+ character `OTP_SECRET`. Do not paste credentials into chat or commit them to Git.
4. Install and start:

```bash
npm install
npm start
```

5. Storefront: `http://localhost:3000`
6. Admin: `http://localhost:3000/admin`

The first server start creates the tables, seeds sample catalog products if the catalog is empty, and creates the first admin user from environment variables. Change sample products and prices before any public launch.

## Deployment

A Render blueprint is included in `render.yaml`. Connect the repository to Render, create the PostgreSQL database and web service, then set the environment variables in the Render dashboard. Use a paid persistent database and a host/network setup that meets W3 SMS's outbound-IP allowlisting requirements. Render free web services and free databases have sleep/expiry and persistence limitations; they are not suitable for live order records.

After the app is deployed, Render provides a temporary `onrender.com` URL even if you do not own a domain. A custom domain can be connected later. Before accepting real orders, test OTP delivery on every mobile operator you intend to support, order creation, stock deduction, admin login, call confirmation, cancellation, and database backups.

## Security checklist still required before public launch

- Set production environment secrets and rotate any credentials exposed during setup.
- Confirm provider network coverage, IP allowlisting, message templates and applicable local compliance.
- Add an all-operator OTP/SMS provider if required.
- Add CSRF token protection, audit logs, automated database backups, monitoring and an order cancellation/restock workflow.
- Configure real customer support email/phone, shipping fees, delivery zones, refund/return policy and privacy policy.
- Add product photography, accurate descriptions, shipping/courier integration and a verified payment gateway if online payments are needed.
- Have an adult account owner review hosting, payment-provider, SMS-provider and business account terms before launch.

## API overview

- `GET /api/products`
- `POST /api/otp/request`
- `POST /api/orders` (verifies OTP server-to-server before creating order)
- `POST /api/admin/login`, `POST /api/admin/logout`, `GET /api/admin/me`
- `GET /api/admin/dashboard`
- `PATCH /api/admin/orders/:id`
- `POST /api/admin/products`, `PATCH /api/admin/products/:id`, `DELETE /api/admin/products/:id`


## Real OTP setup (Bangladesh)

The app uses the W3 SMS REST send endpoint for transactional OTP messages. The provider advertises coverage across Grameenphone, Robi, Banglalink, Airtel and Teletalk; actual delivery depends on the activated account route, balance, sender-ID approval and provider terms. Airtel is part of the Robi network in Bangladesh, but the provider lists it separately.

Set these server-side environment variables before enabling real OTP:
- `W3SMS_API_KEY`: API key from the SMS provider account.
- `W3SMS_SENDER_ID`: sender ID approved for transactional messages.
- `OTP_SECRET`: unique random secret of at least 32 characters.

The server generates a six-digit OTP, stores only an HMAC digest, expires it after five minutes, limits sends and failed attempts, and verifies it server-side before accepting an order. Never put API keys in frontend JavaScript or commit them to Git. Test delivery on SIMs from all four networks before production.

Provider API reference: https://w3sms.com/ (API documentation and account access are available from the provider). This integration has not been live-tested without an issued API key and approved sender ID.
