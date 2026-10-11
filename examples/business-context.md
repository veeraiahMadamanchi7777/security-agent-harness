# Application business context

Replace these prompts with the application's intended rules. Write "unknown" where a rule or deployment detail is not known; do not invent requirements just to complete the template.

## Actors and permissions
- Roles (anonymous, customer, operator, administrator, service account):
- Which actions each role may perform:
- Who owns each resource and how tenant boundaries work:
- Where authentication occurs and how verified identity reaches this application:

## Assets and workflows
- Sensitive data and operations:
- Allowed states and state transitions (for example created → paid → shipped → refunded):
- Required prerequisites for each transition:
- Which rules must hold even when an API is called directly or steps are reordered:

## Prices, balances, payments and quotas
- Authoritative sources of price, discount, tax, balance and account IDs:
- Allowed amounts, currencies, rounding, limits and negative/zero behavior:
- Refund, coupon, credit, withdrawal and quota rules:
- Payment/webhook verification and handling of partially failed operations:

## Replay and concurrency
- Operations that must be idempotent and how keys are scoped:
- Token/OTP/coupon expiration and one-time-use rules:
- Expected concurrent requests, locking, transaction isolation and database constraints:
- External side effects that cannot be rolled back with a database transaction:

## Trust boundaries and environment
- Public, authenticated, internal-only and administrative entry points:
- Gateway/security-filter controls that exist outside the supplied code:
- Network restrictions, deployment assumptions and dependencies not included:
- Known compensating controls and existing security regression tests:
