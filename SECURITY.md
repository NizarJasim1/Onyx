# Security

## Reporting a vulnerability in ONYX

If you find a security problem in ONYX itself (for example, a way to make the scope
guard allow an out-of-scope request, or a way for a crafted target response to run
code or write outside the output directory), please don't open a public issue.

Use GitHub's private vulnerability reporting on this repository instead
(**Security → Report a vulnerability**). Include the version or commit, the steps to
reproduce, and what you expected to happen. I'll reply as soon as I can and credit
you in the fix unless you'd rather stay anonymous.

## Using ONYX responsibly

ONYX sends real, authenticated requests and can change state on the target.

- Only test applications you own, intentionally vulnerable labs, or programs whose
  rules explicitly allow automated testing with multiple accounts.
- Use test accounts you created. Never use other people's credentials.
- Leave dry-run on unless you are sure irreversible actions are allowed.
- Set the scope in the spec as tightly as you can. The scope guard blocks anything
  outside it and treats uncertainty as "don't send".
- `import-har` redacts tokens by default. Don't commit captures or specs with live
  credentials.

Bugs you find with ONYX in someone else's product should go to that vendor through
their disclosure process, not here.
