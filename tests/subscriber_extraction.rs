use std::io::Write;
use std::process::{Command, Stdio};

const REPORTED_HEADER: &str = "\"daxenberger@sip.konvoicepro.eu\" <sip:daxenberger@sip.konvoicepro.eu@92.243.144.4>;tag=ec140-25dcbc";

fn run_packet(from: Option<&str>, to: Option<&str>, args: &[&str]) -> String {
    let info = "(12:00:00.000) W0 in <92.243.144.4:5060> <- 561 bytes from <31.207.116.171:5060>";
    let mut log = format!("{info}\nREGISTER sip:92.243.144.4 SIP/2.0\n");
    for (key, value) in [("From", from), ("To", to), ("P-Asserted-Identity", from)] {
        if let Some(value) = value {
            log.push_str(&format!("{key}: {value}\n"));
        }
    }
    // A subsequent log entry makes xsip process the preceding packet.
    log.push_str(&format!("CSeq: 1 REGISTER\nContent-Length: 0\n\n{info}\n"));

    let mut child = Command::new(env!("CARGO_BIN_EXE_xsip"))
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(log.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "args={args:?}, from={from:?}, to={to:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn display_name_and_extra_uri_at_do_not_crash_filters_or_rendering() {
    let valid_header =
        "\"daxenberger@sip.konvoicepro.eu\" <sip:daxenberger@92.243.144.4>;tag=ec140-25dcbc";
    for header in [REPORTED_HEADER, valid_header] {
        for mode in [None, Some("-R"), Some("--raw")] {
            for filter in ["-n", "--from", "--to"] {
                let mut args = vec![filter, "DAXENBERGER", "-m", "REGISTER"];
                args.extend(mode);
                let output = run_packet(Some(header), Some(header), &args);
                assert!(output.contains("REGISTER"), "args={args:?}");
                if mode == Some("-R") {
                    assert!(output.contains("From: daxenberger To: daxenberger"));
                } else {
                    assert!(output.contains(&format!("From: {header}")));
                    assert!(output.contains(&format!("To: {header}")));
                    assert!(output.contains(&format!("P-Asserted-Identity: {header}")));
                }
            }
            let mut args = vec!["-m", "REGISTER"];
            args.extend(mode);
            assert!(run_packet(Some(header), Some(header), &args).contains("REGISTER"));
        }
    }
}

#[test]
fn quoted_display_delimiters_and_unicode_do_not_affect_subscriber() {
    for (header, subscriber) in [
        (
            r#""Desk \"<sip:wrong@example>;\"" <sip:alice@example.com>;tag=x"#,
            "ALICE",
        ),
        (
            r#""Älice@example.com" <sip:álîce@example.com>;tag=x"#,
            "ÁLÎCE",
        ),
    ] {
        let full = run_packet(Some(header), Some(header), &["-n", subscriber]);
        assert!(full.contains(&format!("From: {header}")));
        let reduced = run_packet(Some(header), Some(header), &["-n", subscriber, "-R"]);
        let value = subscriber.to_lowercase();
        assert!(reduced.contains(&format!("From: {value} To: {value}")));
        assert!(run_packet(Some(header), Some(header), &["-n", "wrong"]).is_empty());
    }
}

#[test]
fn ordinary_number_and_c60_matching_remain_supported() {
    for (header, query) in [
        ("<sip:0471064500@example.com>;tag=x", "471064"),
        ("sip:39C600420770471064400@example.com", "390471064400"),
        ("<sip:39C600420770471064400@example.com>", "C60042077"),
        ("sips:0471064500@example.com", "471064"),
        ("<tel:0471064500>;tag=x", "471064"),
        ("<sip:0471064500;user=phone>", "471064"),
        ("0471064500", "471064"),
    ] {
        for mode in [None, Some("-R")] {
            let mut args = vec!["-n", query];
            args.extend(mode);
            assert!(
                run_packet(Some(header), Some(header), &args).contains("REGISTER"),
                "header={header}, args={args:?}"
            );
        }
    }
}

#[test]
fn number_filters_do_not_match_display_name_host_or_tag() {
    let header = "\"display@example.com\" <sip:alice@host.example.com>;tag=unique-tag";
    for query in ["display", "host.example.com", "unique-tag"] {
        assert!(run_packet(Some(header), Some(header), &["-n", query]).is_empty());
    }
    // The original IP-shaped number query should also complete, even if it does not match.
    assert!(
        run_packet(
            Some(REPORTED_HEADER),
            Some(REPORTED_HEADER),
            &["-n", "31.207.116.171", "-m", "REGISTER"]
        )
        .is_empty()
    );
}

#[test]
fn from_and_to_filters_keep_their_direction() {
    let from = Some("<sip:alice@example.com>");
    let to = Some("<sip:bob@example.com>");
    for (filter, query, matches) in [
        ("--from", "alice", true),
        ("--from", "bob", false),
        ("--to", "bob", true),
        ("--to", "alice", false),
        ("-n", "alice", true),
        ("-n", "bob", true),
    ] {
        assert_eq!(!run_packet(from, to, &[filter, query]).is_empty(), matches);
    }
}

#[test]
fn missing_empty_and_unterminated_headers_have_no_subscriber() {
    for header in [
        None,
        Some(""),
        Some("<sip:>"),
        Some("\"unterminated@example <sip:alice@example.com>"),
    ] {
        assert!(run_packet(header, header, &["-n", "alice"]).is_empty());
        for mode in [None, Some("-R")] {
            let mut args = vec!["-m", "REGISTER"];
            args.extend(mode);
            let output = run_packet(header, header, &args);
            assert!(output.contains("REGISTER"));
            if mode.is_none() {
                if let Some(header) = header {
                    assert!(output.contains(&format!("From: {header}")));
                }
            } else {
                assert!(output.contains("From:  To: "));
            }
        }
    }
}
