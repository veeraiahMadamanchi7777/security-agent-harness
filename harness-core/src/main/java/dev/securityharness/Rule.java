package dev.securityharness;

enum Rule {
    SQLI("sqli", 89, "High", "Use constant SQL/JPQL with bound parameters, not concatenated request values."),
    RCE("rce", 78, "High", "Use a fixed executable and allowlisted arguments; avoid shells and attacker-controlled command selection."),
    PATH("pathtraversal", 22, "High", "Resolve under an allowed base directory and verify containment, including symlinks, before file operations."),
    DESERIAL("deserial", 502, "High", "Replace native deserialization of untrusted data with an explicit schema; otherwise enforce an ObjectInputFilter allowlist."),
    REDIRECT("openredirect", 601, "Medium", "Map destination identifiers to fixed local URLs or strictly allowlist scheme, host and path."),
    XSS("xss", 79, "Medium", "Verify response content type and encode for the actual HTML, attribute or JavaScript output context."),
    SSRF("ssrf", 918, "High", "Allowlist destinations and schemes, block private/link-local addresses, and revalidate redirects and DNS resolution."),
    LDAP("ldap", 90, "High", "Use parameterized LDAP filters with separate values; escape distinguished names and filters for their distinct contexts."),
    TEMPLATE("templateinject", 94, "High", "Keep script/template source fixed and pass untrusted values only as data; disable untrusted script execution."),
    XXE("xxe", 611, "Medium", "Verify parser factory configuration disables external DTDs/entities and external schema access before parsing untrusted XML."),
    CRYPTO("crypto", 327, "Medium", "Use modern algorithms appropriate to the security purpose, such as AES-GCM for encryption; review keys and nonces separately."),
    SECRET("secrets", 798, "High", "Remove the credential literal, rotate it if real, and use a managed secret store or runtime configuration.");
    final String skill, severity, fix;
    final int cwe;
    Rule(String skill, int cwe, String severity, String fix) { this.skill = skill; this.cwe = cwe; this.severity = severity; this.fix = fix; }
}
