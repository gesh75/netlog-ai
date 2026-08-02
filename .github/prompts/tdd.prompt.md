---
mode: agent
description: Write failing tests first for a change (TDD)
---

Practice strict TDD for the change I describe.

1. Restate the behavior in one sentence.
2. Write the tests **first**, covering happy path, boundaries, and error paths.
3. Run them and show me they fail for the right reason - not an import or syntax error.
4. Write the minimum implementation to make them pass.
5. Run the full suite and report coverage for the touched module.
6. Refactor only once green, re-running tests after each step.

Do not write implementation code before step 3 has actually been executed.
