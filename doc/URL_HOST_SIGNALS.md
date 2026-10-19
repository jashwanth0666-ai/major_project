# URL hostname signals

The URL assessment adds a `urlHostSignals` source with a check time, normalized ASCII host, and zero or more explainable heuristic signals. These are suspicion indicators, not model attribution, a malware classification, or proof of safety. High-severity final-host or observed redirect-host signals can raise policy to WARN; a BLOCK requires corroboration from a model score at or above its configured threshold.

Current signals:

- `IDN_PUNYCODE` (low): one or more internationalized labels use Punycode. IDNs are common and can be legitimate; inspect the displayed Unicode form.
- `MIXED_CONFUSABLE_SCRIPT` (high): one label mixes Latin with Greek or Cyrillic characters, which can make a hostname resemble another one.
- `IDN_BRAND_HOMOGRAPH` (high): the registrable domain decodes to Greek/Cyrillic characters whose limited confusable skeleton matches a configured well-known brand name.
- `BRAND_LOOKALIKE_DOMAIN` (high): the registrable label exactly or within one edit resembles a configured brand name.
- `BRAND_NAME_IN_SUBDOMAIN` (medium): a configured brand name appears in a subdomain while the registrable domain differs.
- `BRAND_NAME_IN_DOMAIN` (medium): the registrable label joins a configured brand name with other text using a hyphen.
- `USERINFO_PRESENT` (medium): the URL contains user information before the actual host, a URL form that can disguise the destination in some interfaces.
- `DEEP_SUBDOMAIN_CHAIN` (low): more than five hostname labels are present. This is a review hint, not evidence of maliciousness.

Brand checks use a small built-in list of well-known brands and a limited Greek/Cyrillic mapping; they do not provide general visual similarity, a public-suffix-list implementation, or coverage of all Unicode confusables. The checks do not fetch pages, follow redirects, or inspect DNS. A lack of signals does not mean a URL is safe. Signals are recorded separately from the ML and optional reputation results.

When the browser extension is installed, it may also submit up to six observed main-frame redirect hostnames. Spring checks intermediate hosts with the same local heuristics and returns matching signals under `redirectHostSignals`. Hostnames are browser-reported context; redirects without a matching heuristic do not change policy. No redirect path, query, fragment, or credential is included.
