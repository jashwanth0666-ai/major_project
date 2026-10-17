# URL hostname signals

The URL assessment adds a `urlHostSignals` source with a check time, normalized ASCII host, and zero or more explainable heuristic signals. These are suspicion indicators, not model attribution, a malware classification, or proof of safety. They do not change policy verdicts.

Current signals:

- `IDN_PUNYCODE` (low): one or more internationalized labels use Punycode. IDNs are common and can be legitimate; inspect the displayed Unicode form.
- `MIXED_CONFUSABLE_SCRIPT` (high): one label mixes Latin with Greek or Cyrillic characters, which can make a hostname resemble another one.
- `USERINFO_PRESENT` (medium): the URL contains user information before the actual host, a URL form that can disguise the destination in some interfaces.
- `DEEP_SUBDOMAIN_CHAIN` (low): more than five hostname labels are present. This is a review hint, not evidence of maliciousness.

The checks do not fetch pages, follow redirects, inspect DNS, or use a brand allowlist. They do not attempt general visual similarity or all Unicode confusable mappings. A lack of signals does not mean a URL is safe. The signals are recorded separately from the ML result and the optional reputation result.
