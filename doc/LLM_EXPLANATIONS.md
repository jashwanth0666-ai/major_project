# Cloud assessment explanations

AI WatchDog can optionally generate a short, structured explanation of the
existing assessment. The cloud model is an explanation layer only: XGBoost,
the existing risk score, reputation evidence, and the policy engine remain
authoritative. The generated text cannot change the model output or policy
verdict.

## Enable on Windows

Create a local `.env` file from `.env.example` and set the variables below.
Spring Boot imports the repository-root `.env` when launched from the normal
backend working directory. Do not commit `.env` or share the key. For a
non-standard working directory, set the variables in PowerShell instead:

```powershell
$env:AIWATCHDOG_LLM_ENABLED = "true"
$env:AIWATCHDOG_LLM_API_KEY = "<your-key>"
$env:AIWATCHDOG_LLM_MODEL = "openai/gpt-oss-120b"
$env:AIWATCHDOG_LLM_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
$env:AIWATCHDOG_LLM_TIMEOUT_MS = "3000"
cd backend
.\mvnw.cmd spring-boot:run
```

The feature is disabled by default and the application remains functional
without a key. `AIWATCHDOG_LLM_ENDPOINT` is optional and must be an HTTPS
endpoint with the OpenAI Chat Completions response shape. The default endpoint
is Groq's OpenAI-compatible API and the default model is
`openai/gpt-oss-120b`. The key is sent only from Spring Boot and is never
returned to clients or included in the evidence payload.

The response adds `explanationDetails` with `summary`,
`supportingEvidence`, `uncertainties`, `recommendedAction`, `generatedBy`, and
`fallbackUsed`. When disabled, unavailable, timed out, rate-limited, or given
invalid output, deterministic rule-based content is returned with
`generatedBy: "rules"` and `fallbackUsed: true`. Provider failures are not
reported as clean evidence.

Only redacted subject data, model fields, existing reasons, policy context, and
normalized reputation status are sent. URL query strings, fragments, page
contents, cookies, credentials, local paths, and raw provider exceptions are
excluded. Reputation metadata is treated as untrusted data and cannot provide
instructions to the model.

## Disable or roll back

Set `AIWATCHDOG_LLM_ENABLED=false` or remove the key, then restart Spring Boot.
No database migration or model change is required. The original assessment
endpoint and deterministic explanation remain available.

## Verification

Use a mocked HTTPS-compatible provider in automated tests or a controlled
development endpoint. Do not use real malicious sites or put credentials in
requests, logs, tests, or screenshots. This change was not executed or tested
in this development session, as requested; run the repository's existing
backend test command before enabling the feature.
