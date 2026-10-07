## Context

Five extraction blocks independently locate a scheme and delimiters in the whole header. An `@` in a display name can precede the scheme and create a reversed slice. Fixing only filters leaves full and reduced output vulnerable.

## Goals / Non-Goals

**Goals:** Share safe subscriber ranges across filtering and display; keep original log values, case-insensitive matching, and C60 matching; keep the production change local and dependency-free.

**Non-Goals:** Full SIP validation, repairing invalid URIs, percent-decoding usernames, or changing duplicate-header handling.

## Decisions

- Add one helper returning an optional byte range in the original header. Locate an angle-bracketed URI outside quoted display names, or use a bare URI. Ignore escaped quotes when locating the opening bracket.
- Support SIP, SIPS, and TEL schemes and retain plain-number extraction. Search for the first `@` within the URI; if absent, stop at a parameter delimiter or the URI end. Preserve the first-`@` convention for the reported malformed URI, extracting `daxenberger`.
- Check ranges with `str::get`. Unextractable headers produce an empty filter subscriber and retain their original text in full output; reduced output uses an empty subscriber. Returning ranges also lets highlighting preserve the display name, host, and parameters exactly.
- Replace the five extraction blocks with the helper. A bounds-only guard would avoid the panic but still lose valid matches; a full SIP parser would add unnecessary scope and dependencies.
- Verify both helper behavior and the actual CLI using synthetic Cirpack packets, then run the rebuilt binary on the supplied log.

## Risks / Trade-offs

- Malformed URIs remain ambiguous → retain the established first-`@` behavior and preserve the full header for inspection.
- General SIP parsing and unrelated formatter assumptions remain outside this fix → test the affected filter and rendering paths without claiming complete malformed-input validation.
- The input log is private and large → keep it out of the repository; use synthetic fixtures in committed tests.
