# crAPI corpus — provenance (third-party, retrieved verbatim)

These artifacts are crAPI's OWN published specification and behavior, retrieved
verbatim (not authored by ONYX). They are the third-party ground truth for the
offline conformance validation.

- `crapi-openapi-spec.json`
  source: https://raw.githubusercontent.com/OWASP/crAPI/refs/heads/develop/openapi-spec/crapi-openapi-spec.json
  publisher: OWASP/crAPI (the target's own authors)
  retrieved: 2026-06-29 via web_fetch
  role: the authoritative API contract — endpoints, methods, security, response
        codes, and real example payloads. Ownership-enforcement is derivable from
        which endpoints define a 403 "not allowed" response and which return other
        users' data in their examples.

Independent corroboration (assessment write-ups, cited for the labels):
- mechanic_report BOLA, vehicle-location BOLA, dashboard-clean:
  medium.com/@SALMA_DOUMI, medium.com/@josegpach, csbygb.gitbook.io (pentips)
- admin video delete BFLA, video field exposure: csbygb pentips, owasp.org/crapi
