This is an intentionally vulnerable source-only fixture, not a running payment service.

Business rules:
- An authenticated customer may pay only their own order or withdraw from their own wallet.
- Authentication is enforced at the gateway, but ownership checks must be implemented in this service. Gateway authentication does not perform object-level authorization.
- Order.totalCents is the authoritative server-calculated purchase price. A smaller client-supplied amount must never mark the order paid.
- A withdrawal amount must be strictly positive. A request must never increase a wallet balance.
- PaymentGateway.charge throws on processor failure, but it does not check the order price, ownership, or previous payment state.
- Repository interfaces contain no implicit authorization. Deployment concurrency/locking behavior is unspecified: report race concerns as assumptions rather than proven behavior.
