## Why

SIP headers with an `@` in their display name make xsip slice backwards and panic, aborting log processing. This occurs with valid SIP URIs as well as the reported malformed URI containing two unescaped `@` characters.

## What Changes

- Share subscriber extraction between From/To filters, full header highlighting, and reduced output.
- Find delimiters within the URI rather than the display name, and use checked ranges.
- Preserve original headers and tolerate malformed input without interpreting an additional `@` as a new feature.
- Add focused extraction and CLI regression coverage.

## Capabilities

### New Capabilities

- `sip-subscriber-extraction`: Safely extract subscriber values for filtering and display, including headers with display names and malformed URIs.

### Modified Capabilities

None; this repository has no existing OpenSpec specifications.

## Impact

Localized changes in `src/main.rs`, CLI regression tests, and OpenSpec artifacts. No new dependencies or CLI options; normal case-insensitive matching and C60 handling remain supported.
