# Application business context — Example (E-commerce Checkout)

This is a filled-in example of `business-context.md` for an imaginary e-commerce platform.
Use it as a reference for the level of detail expected by `--business-context`.

---

## Actors and permissions

- **Roles:** anonymous (browse only), customer (registered, can purchase), operator (customer support, can issue refunds up to $500, cannot change prices), administrator (full access including price management and bulk operations), payment-service (internal service account, webhook only).
- **Which actions each role may perform:**
  - anonymous: view products, add to cart (session-scoped), initiate checkout (redirected to login)
  - customer: place orders, view own order history, apply valid coupon codes, request refunds within 30 days of delivery
  - operator: view any order, issue refunds ≤ $500, update shipping address before dispatch, cannot modify order amounts or product prices
  - administrator: all above plus price management, coupon creation/expiry, user account management, bulk CSV order export
  - payment-service: POST /webhooks/payment only, validated by shared HMAC-SHA256 secret in `X-Payment-Signature` header
- **Resource ownership:** Orders belong to the customer who created them. Operators may view but not modify items. Cart is session-scoped; cart contents are transferred to the authenticated user on login.
- **Authentication:** Spring Security session-based auth. JWT issued on login, validated on every API call. Session invalidated on logout.

---

## Assets and workflows

- **Sensitive data:** credit card last-4 and expiry (stored), full card data never stored (handled by payment gateway). Order totals, customer PII (name, address, email), coupon discount values.
- **Allowed order state transitions:**
  - `PENDING` → `PAYMENT_AUTHORIZED` → `PAID` → `DISPATCHED` → `DELIVERED` → `REFUND_REQUESTED` → `REFUNDED`
  - `PENDING` → `CANCELLED` (before `PAID`)
  - No transition backwards except `REFUND_REQUESTED` → `REFUNDED` (triggered by webhook only)
- **Required prerequisites per transition:**
  - `PENDING` → `PAYMENT_AUTHORIZED`: valid payment method, non-zero positive total, all items in stock
  - `PAID` → `DISPATCHED`: warehouse confirmation only (internal, not customer-triggered)
  - `DELIVERED` → `REFUND_REQUESTED`: customer-initiated, order age ≤ 30 days, item not marked non-refundable
  - `REFUND_REQUESTED` → `REFUNDED`: webhook from payment provider only, HMAC verified, idempotency key checked
- **Invariants that must hold even when API is called directly:**
  - Order total = sum(item.price × item.quantity) + shipping − discount. Never trust client-submitted total.
  - Coupon discount may not reduce total below $0.01.
  - Each coupon code may be used at most once per customer account.
  - An order's `customerId` must equal the authenticated user's ID. No cross-customer order access.

---

## Prices, balances, payments and quotas

- **Authoritative sources:** Product prices read from `product_catalog` table at checkout time, not from client request. Discount amounts read from `coupon` table keyed by code, not from request body.
- **Allowed amounts:** Order total must be > $0. Negative quantities and zero-price line items are not valid. Maximum single order value is $10,000 (enforced server-side).
- **Refund rules:** Refund amount must equal original order total (full refund only). Partial refunds not supported. Refund issued via payment gateway API; `REFUNDED` status set only after webhook confirms success.
- **Coupon rules:** One-time use per customer. Expiry date enforced server-side. Percentage discounts capped at 100%. Fixed-amount discounts cannot reduce total below $0.01.
- **Payment/webhook:** Payment provider sends `POST /webhooks/payment` with `X-Payment-Signature: sha256=<hmac>`. Signature verified before any state change. Idempotency key (`X-Idempotency-Key`) stored; duplicate keys return 200 without reprocessing.

---

## Replay and concurrency

- **Idempotent operations:** Webhook handler is idempotent; duplicate delivery of `payment.succeeded` must not double-fulfill. Idempotency key stored in `webhook_events` table with a unique constraint.
- **Token/coupon expiry:** Coupon expiry enforced at redemption time, not at cart-add time. OTP codes (2FA) expire after 5 minutes, single-use only, stored with `used_at` timestamp.
- **Concurrency:** High-traffic flash sales can cause concurrent checkout for the same low-stock item. Inventory decrement uses `UPDATE products SET stock = stock - 1 WHERE id = ? AND stock > 0` with row-level locking. If 0 rows updated, checkout fails.
- **Transaction isolation:** Order placement runs in `SERIALIZABLE` isolation to prevent phantom reads on stock levels. Refund state transitions use `SELECT ... FOR UPDATE` on the order row.
- **External side effects:** Payment gateway charge is made inside the transaction intent but confirmed asynchronously via webhook. If the DB commit succeeds but the gateway call fails, a compensating cancel is attempted. If both fail, the order stays in `PAYMENT_AUTHORIZED` and is flagged for manual review.

---

## Trust boundaries and environment

- **Public endpoints (no auth):** `GET /products/**`, `GET /search`, `POST /cart/**` (session only), `POST /webhooks/payment` (HMAC-authenticated service account).
- **Authenticated endpoints (customer):** `POST /checkout`, `GET /orders/{orderId}`, `POST /orders/{orderId}/refund`.
- **Operator endpoints:** `GET /admin/orders/**`, `POST /admin/orders/{orderId}/refund` (≤ $500 limit enforced in service layer).
- **Admin-only endpoints:** `POST /admin/prices/**`, `POST /admin/coupons/**`, `GET /admin/export/orders`.
- **Controls outside the supplied code:** API gateway enforces rate limiting (100 req/min per IP). WAF blocks known SQLi/XSS signatures. TLS termination at load balancer; all internal traffic is HTTP.
- **Network restrictions:** Payment service webhook originates from a known IP range (configured in `application.yml`). Admin endpoints are additionally restricted by VPN IP allowlist at the load balancer (not in code).
- **Known compensating controls:** All order mutations are audit-logged to an append-only `audit_log` table. PCI compliance scope reduced by tokenizing card data at the gateway before it reaches the application.
- **Existing security regression tests:** `OrderServiceSecurityTest.java` covers cross-customer access, negative amount rejection, and coupon double-use. Webhook HMAC validation tested in `PaymentWebhookControllerTest.java`.
