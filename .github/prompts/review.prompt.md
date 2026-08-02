---
mode: agent
description: Security and quality review of the current changes
---

Review the current diff (`git diff` plus staged changes) and report findings ordered by severity.

Check, in this order:

1. **Secrets** - hardcoded keys, tokens, passwords, connection strings, in code *or* tests.
2. **Injection** - SQL/shell/path built by string concatenation from untrusted input.
3. **Boundary validation** - external input used without validation.
4. **Error handling** - swallowed exceptions, bare `except`, missing failure paths.
5. **Mutation** - functions that modify their arguments in place.
6. **Size** - functions over 50 lines, files over 800 lines, nesting deeper than 4.
7. **Test coverage** - new behaviour with no accompanying test.

For each finding give: `file:line`, severity (CRITICAL/HIGH/MEDIUM/LOW), the concrete failure
scenario, and the minimal fix. If a category is clean, say so in one line - do not pad the report.
