# Ground-truth review protocol

`ground_truth.json` is the benchmark oracle. Each case must be reviewed against the exact handler branch in `run_lab.py`; scanner output must never be used to generate or approve expectations.

For every case, a maintainer should verify:

1. The route is reachable from `/` and uses only loopback resources.
2. The positive behavior independently satisfies the named rule's evidence contract.
3. A negative case does not contain the vulnerable behavior, not merely that the scanner misses it.
4. Rule ID and normalized path match the finding emitted by the scanner.
5. Synthetic credentials and data cannot authenticate to any real service.

After human review, replace `curation.human_signoff` with the reviewer's name or team and add `human_reviewed_at` in ISO date format. Any fixture behavior change must increment `version` and invalidate the previous sign-off.

The current cases were manually audited from source by Codex, but `human_signoff` intentionally remains `pending`. Do not describe the dataset as human-reviewed until a maintainer completes this checklist.

## Current baseline

Version `2026-10-28.2` contains 24 reviewed locations: 20 positives and 4 explicit negatives across authorization, XSS, and classic injection families. New hunt fixtures cover generic-parameter XSS (`/echo?msg=`), unauthenticated object access (`/api/private/7`), dual-session overlap on orders/private objects, and neighbor ID mutation (`/api/orders/100` → `101`). The accepted baseline remains precision 1.0, recall 1.0, and F1 1.0 on this controlled fixture only and must be reported with the version and scope.
