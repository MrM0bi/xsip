## ADDED Requirements

### Requirement: Subscriber extraction excludes display names

From/To filtering and full and reduced display SHALL extract the subscriber from the URI, ignoring delimiters in the display name. Ordinary case-insensitive number and C60 matching SHALL remain supported.

#### Scenario: Display name contains an email address
- **WHEN** a header is `"alice@example.com" <sip:alice@example.com>`
- **THEN** xsip extracts `alice`, matches a subscriber filter for `ALICE`, and renders full and reduced output without a panic

#### Scenario: Display name contains quoted URI-like text
- **WHEN** a quoted display name contains `:`, `@`, `;`, or angle brackets before the actual URI
- **THEN** extraction uses the actual URI and preserves the display name in full output

#### Scenario: Normal number and C60 matching
- **WHEN** ordinary numeric or C60 subscriber headers are filtered
- **THEN** existing substring matching and removal of the C60 segment for a non-C60 search continue to work

### Requirement: Malformed URI extraction is safe and preserves evidence

The affected extraction paths SHALL tolerate the reported extra URI `@` without panicking or rewriting the original header. They SHALL use the first `@` inside the URI as the subscriber boundary. When extraction fails, filtering SHALL use an empty subscriber and full output SHALL preserve the original header text.

#### Scenario: Reported malformed header
- **WHEN** a header is `"daxenberger@sip.konvoicepro.eu" <sip:daxenberger@sip.konvoicepro.eu@92.243.144.4>;tag=ec140-25dcbc`
- **THEN** extraction yields `daxenberger`, subscriber filtering and both output modes complete, and full output retains the original header value

#### Scenario: Missing or unextractable subscriber
- **WHEN** a subscriber header is absent, empty, or has an unterminated quoted display name
- **THEN** extraction supplies no subscriber, ordinary positive subscriber filters do not match that header, and rendering does not panic

#### Scenario: Unicode display name and subscriber
- **WHEN** a header contains non-ASCII display-name or subscriber characters
- **THEN** extraction uses valid UTF-8 boundaries and renders the header without a slicing panic
