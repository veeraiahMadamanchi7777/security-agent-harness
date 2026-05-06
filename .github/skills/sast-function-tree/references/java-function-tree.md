# Java Function Tree Reference

## Function Roots

Treat these as roots:

- Spring MVC/WebFlux controllers.
- JAX-RS resources.
- Servlet `doGet`, `doPost`, filters, listeners.
- GraphQL query and mutation resolvers.
- gRPC service implementations.
- Message listeners: Kafka, RabbitMQ, JMS.
- Scheduled jobs.
- Startup runners.
- Webhook handlers.
- File import and export flows.

## High-Risk Node Signals

Raise review priority when a function:

- Accepts external input.
- Makes authorization or tenant decisions.
- Reads, writes, or deletes files.
- Executes queries or dynamic query builders.
- Calls outbound URLs or sockets.
- Parses XML, YAML, serialized objects, or templates.
- Executes commands, scripts, expressions, or reflection.
- Mutates balances, roles, ownership, workflow status, quotas, or security settings.
- Handles credentials, tokens, keys, password reset, MFA, or session state.

## Tree Notation

Use compact call-tree notation:

```text
Controller.getInvoice(id) [source: @PathVariable id, auth: authenticated]
└─ InvoiceService.loadInvoice(id, principal) [control: owner check? UNKNOWN]
   ├─ InvoiceRepository.findById(id) [sink: DB read]
   └─ PdfService.render(invoice) [sink: template/render]
```

## Human Review Heuristics

- Similar functions should have similar controls. Differences are interesting.
- Controller-only authorization is fragile when services are reused.
- Repository methods that include `tenantId` or `ownerId` are stronger than post-load checks.
- Functions with no direct entry point may still be reachable through jobs, listeners, tests reused in prod, reflection, or framework wiring.
