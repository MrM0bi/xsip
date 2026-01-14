use chrono::{Local, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use clap::builder::styling::{self, AnsiColor};
use clap::Parser;
use clap::CommandFactory;
use clap::FromArgMatches;
use std::collections::HashSet;
use flate2::read::GzDecoder;
use indexmap::IndexMap;
use ipnet::Ipv4Net;
use notify::event::{AccessKind, AccessMode};
use regex::Regex;
extern crate atty;
use core::time;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::io::{self, BufRead, BufReader, ErrorKind, Write};
use std::str::Split;
use std::{fs, thread, usize};
use std::io::Seek;
use std::sync::atomic::{AtomicU64, Ordering};
use notify::{EventKind, RecursiveMode, Watcher};
use std::{path::Path, sync::Arc};
use colored::*;


const SIP_METHODS: &[&str] = &["INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "PRACK", "UPDATE", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE"];

const STYLES: styling::Styles = styling::Styles::styled()
    .header(AnsiColor::Yellow.on_default())
    .usage(AnsiColor::Green.on_default())
    .literal( AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Cyan.on_default());


/// A command-line tool to extract, filter and Pretty-print SIP messages from Cirpack pcscf.1 and ibcf.1 log files.
/// 
/// DESCRIPTION
///   Most flags can take more than one value, these can be separated either by a colon `,` or a whitespace ` `.
///   Every flag can only be used once (Even when using --NOT).
/// 
///   By default, every given flag combined with AND logic (if --OR is not provided). Multiple arguments of the same flag are evaluated with OR logic.
///   Example:
///   - `xsip /home/log/pcscf.1 -m INVITE ACK`                  : Shows all Packets where the SIP-Method either matches INVITE or ACK
///   - `xsip /home/log/pcscf.1 -m INVITE,ACK -c a2f7d0f89e5a3` : Shows all Packets where the SIP-Method either matches INVITE or ACK and the Call-ID is a2f7d0f89e5a3
/// 
///   Although input through stdin is supported, this should only be used with static input. The use of `tail -f ibcf.1 | xsip` discouraged, as tail tends to pass duplicate lines when the file is truncated.
///   It is generally recommended to read from a file directly, as it should be a lot faster and supports hot-reloading deleted and recreated files when using the `-f` flag. 
///    
///   All Filters are generally Case-insensitive. Only the "-c, --call-id" Flag ist Case-sensitive.
/// 
///   Multiple SIP-Headers with the same name are supported, filtering by them may be a bit flaky.
/// 
/// EXAMPLE
///   `xsip /home/log/pcscf.1 -f --int -m REGISTER -n 0471234567;`  : Follows the file and shows all external and internal REGISTER Requests from a specific number
///   `xsip /home/log/pcscf.1 -a 200 -q INVITE -i 151.123.321.123;` : Lists all '200 OK' Responses to previous INVITEs that where sent from/to IP 151.123.321.123
///   `xsip /home/log/pcscf.1 -s "Asterisk";`                       : Lists all Packets containing the String "Asterisk" somewhere
#[derive(Parser, Debug)]
#[command(author="Benjamin H.", version=env!("CARGO_PKG_VERSION"), about, verbatim_doc_comment, override_usage="xsip [INPUT_FILE] [OPTIONS]",styles=STYLES)]
struct Args {

    /// Path of pcscf.1 / ibcf.1 Log-file
    input_file: Option<PathBuf>,

    /// Follow growing Files; similar to `tail -f`
    /// 
    ///   Hot-reloads deleted and recreated / moved files. Usefull with pcscf.1 / ibcf.1 Log-file when monitoring, 
    ///   since those get archived (moved) once every hour.
    #[arg(short, long, verbatim_doc_comment)]
    follow: bool,


    /// Join Filters with OR; Default: AND
    #[arg(long = "OR", verbatim_doc_comment)]
    or_filter: bool,

    /// Exclude Packets matching the Filters after the --NOT Parameter
    /// 
    ///   Inverts the logic of filters coming after it. 
    ///   When Using the same Flag multiple times only the first use will be considered. 
    ///   Example: -i 10.137.228.135 --NOT -m OPTIONS,OK    maches if either Source or Destination IP are "10.137.228.135" but ignores OPTIONS and OK Packtes
    #[arg(long = "NOT", verbatim_doc_comment)]
    not_filter: bool,


    /// Filter Packets by number (From or To)
    /// 
    ///   Filters using "contains" (works with/around c60 numbers)
    ///   Example: -n "471064"    matches "0471064500" and "39C600420770471064400"
    #[arg(short, long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    number: Option<Vec<String>>,

    /// Filter Packets by From-number
    /// 
    ///   Filters using "contains"
    ///   Example: --from "471064"    matches "0471064500" and "39C600420770471064400"
    #[arg(long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    from: Option<Vec<String>>,

    /// Filter Packets by To-number
    /// 
    ///   Filters using "contains"
    ///   Example: --to "471064"    matches "0471064500" and "39C600420770471064400"
    #[arg(long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    to: Option<Vec<String>>,


    /// Filter Packets by IP (SRC or DST)
    /// 
    ///   Parses the given IP to a Single IP-Address or a Range. Supports CIDR-Notation
    ///   Filters using "exact match" for single IPs and "contains" with a Range of IPs.
    ///   Example: -i "92.243.167.83"    matches if either Source or Destination IP are "92.243.167.83"
    ///            -i "10.50.16.0/24"    matches if either Source or Destination IP are inside the Range "10.50.16.0-255"
    #[arg(short, long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    ip: Option<Vec<String>>,

    /// Filter Packets by SRC IP
    /// 
    ///   Parses the given IP to a Single IP-Address or a Range. Supports CIDR-Notation
    ///   Filters using "exact match" for single IPs and "contains" with a Range of IPs.
    ///   Example: -i "92.243.167.83"    matches if Source IP is "92.243.167.83"
    ///            -i "10.50.16.0/24"    matches if Source IP is inside the Range "10.50.16.0-255"
    #[arg(long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    srcip: Option<Vec<String>>,

    /// Filter Packets by DST IP
    /// 
    ///   Parses the given IP to a Single IP-Address or a Range. Supports CIDR-Notation
    ///   Filters using "exact match" for single IPs and "contains" with a Range of IPs.
    ///   Example: -i "92.243.167.83"    matches if Destination IP is "92.243.167.83"
    ///            -i "10.50.16.0/24"    matches if Destination IP is inside the Range "10.50.16.0-255"
    #[arg(long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    dstip: Option<Vec<String>>,

    
    /// Filter Packets by Port (SRC or DST)
    /// 
    ///   Filters using "exact match"
    ///   Example: -p "5060"    matches if either Source or Destination Port are "5060"
    #[arg(short, long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    port: Option<Vec<u16>>,

    /// Filter Packets by SRC Port
    /// 
    ///   Filters using "exact match"
    ///   Example: --srcport "5060"    matches if Source Port is "5060"
    #[arg(long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    srcport: Option<Vec<u16>>,

    /// Filter Packets by DST Port
    /// 
    ///   Filters using "exact match"
    ///   Example: --destport "5060"    matches if Destination Port is "5060"
    #[arg(long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    dstport: Option<Vec<u16>>,


    /// Filter Packets by Call-ID
    /// 
    ///   Filters using "contains"
    ///   Example: -c "GA-006d5207"    matches "GA-006d5207" or "07745-GA-006d5207-6d4289c74"
    #[arg(short, long = "cid", num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    call_id: Option<Vec<String>>,

    /// Filter Packets by SIP Method or Response Text (REGISTER, INVITE, OPTIONS, etc.; Trying, Nonce, etc. )
    /// 
    ///   Filters using "contains"
    ///   Example: -m "EGIST"    matches "REGISTER" or "Invalid Register"
    #[arg(short, long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    method: Option<Vec<String>>,

    /// Filter Packets by Response Status Code (302, 404, 5, etc.)
    /// 
    ///   Filters using "starting_with"
    ///   Example: -m "302"    matches all Responses with Status Codes "302"
    ///            -m "5"    matches all Responses with Status Codes that begin with 5 "500", "502" etc.
    #[arg(short = 'a', long, num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    status_code: Option<Vec<String>>,

    /// Filter Packets by CSeq Sequence number or Method (2547 or REGISTER, INVITE, OPTIONS, etc.)
    /// 
    ///   The Sequence number is a sometimes random but always increasing number that every Request comes with (ex. an INVITE 
    ///   that has the SeqNum 2547). When sending a Response, it can thus be used to refer to this specific request. This way you can
    ///   search for a specific transaction.
    ///   Filters using "contains"
    ///   Example: -m "EGIST"    matches "REGISTER"
    ///            -m "2547"    matches Sequence number "2547" (Response to Package with number 2547)
    #[arg(short = 'q', long = "cseq", num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    cseq_method: Option<Vec<String>>,

    /// Filter (Raw) Packets by String (case-insensitive)
    /// 
    ///   Filters using "contains"
    ///   Searches line by line for the given text. Maches the whole Packet if one line contains it.
    #[arg(short, long = "string-search", num_args=1.., value_delimiter=',', verbatim_doc_comment)]
    string: Option<Vec<String>>,

    /// Filter (Raw) Packets by RegEx (case-sensitive)
    /// 
    ///   Filters using "contains/regex"
    ///   Searches line by line for the given text with Regex. Maches the whole Packet if one line matches.
    #[arg(short, long = "regex-search", verbatim_doc_comment)]
    regex: Option<String>,

    /// Filter Packets by Time
    /// 
    ///   Pass two time values separated by an underscore `_`. Like '-t 12:48_13:25' or '-t _15:37'.
    ///   A Time has to be formatted in one of the following Ways: '13', '13:07' or '13:07:21'.
    ///   Not providing a value on one side filters from/to the beginning/end of the file to/from the given time.
    #[arg(short, long, value_delimiter='_', verbatim_doc_comment, verbatim_doc_comment)]
    time: Option<Vec<String>>,

    /// Match only Request Packets
    #[arg(long)]
    request: bool,

    /// Match only Response Packets
    #[arg(long)]
    response: bool,


    /// Do not Filter Packets by external IPs, show Pakets between private IPs too
    #[arg(long = "int")]
    internal: bool,


    /// Filter Packets by SDP, only show the ones that have SDP
    #[arg(long)]
    hassdp: bool,


    /// Prints the Packets Info line and Basic SIP Headers only 
    #[arg(short = 'R', long = "reduced")]
    print_reduced: bool,

    /// Prints the Packets "Raw" like they where provided in the input
    #[arg(long = "raw")]
    print_raw: bool,

    /// Prints the Packets but without SDP (this is not a filter, just a different display mode)
    #[arg(long = "nosdp")]
    nosdp: bool,
}



struct Packet {
    time: NaiveDateTime,
    srcip: Ipv4Addr,
    srcport: u16,
    dstip: Ipv4Addr,
    dstport: u16,
    payload_size: u32,
    outgoing: bool,
    sip_method: String,
    sip_version: String,
    request_uri: String,
    isresponse: bool,
    response_code: String,
    response_text: String,
    sip: IndexMap<String, String>,
    sdp: Vec<String>,
    other: Vec<String>,
    filter_out: bool,
    error: bool,
    error_text: String
}


impl Packet {
    pub fn new() -> Self {
        Packet { 
            time: NaiveDateTime::new(NaiveDate::from_ymd_opt(1970, 1, 1).unwrap(), NaiveTime::from_hms_milli_opt(0, 0, 0, 0).unwrap()), 
            srcip: Ipv4Addr::new(0, 0, 0, 0), 
            srcport: 0, 
            dstip: Ipv4Addr::new(0, 0, 0, 0), 
            dstport: 0, 
            payload_size: 0, 
            outgoing: false,
            sip_method: String::new(),
            sip_version: String::new(),
            request_uri: String::new(),
            isresponse: false,
            response_code: String::new(),
            response_text: String::new(),
            sip: IndexMap::new(), 
            sdp: Vec::new(),
            other: Vec::new(),
            filter_out: false,
            error: false,
            error_text: String::new()
        }
    }

    pub fn reset(&mut self) {
        self.time = NaiveDateTime::new(NaiveDate::from_ymd_opt(1970, 1, 1).unwrap(), NaiveTime::from_hms_milli_opt(0, 0, 0, 0).unwrap());
        self.srcip = Ipv4Addr::new(0, 0, 0, 0);
        self.srcport = 0;
        self.dstip = Ipv4Addr::new(0, 0, 0, 0);
        self.dstport = 0;
        self.payload_size = 0; 
        self.outgoing = false;
        self.sip_method = "".to_string();
        self.sip_version = "".to_string();
        self.request_uri = "".to_string();
        self.isresponse = false;
        self.response_code = "".to_string();
        self.response_text = "".to_string();
        self.sip.clear();
        self.sdp.clear();
        self.other.clear();
        self.filter_out = false;
        self.error = false;
        self.error_text = "".to_string();
    }

}





fn color_response_method(response_code: &String, response_text: &String) -> String {

    let response_code_int: i16 = response_code.parse().unwrap_or(-1);

    let spaced_response_text: String = format!(" {} ", response_text);
    
    match response_code_int {
        x if x >= 600 => format!("{} {}", response_code.truecolor(177, 44, 201), spaced_response_text.truecolor(255, 255, 255).on_truecolor(177, 44, 201)), // Magenta
        x if x >= 500 => format!("{} {}", response_code.truecolor(244, 67, 54), spaced_response_text.truecolor(255, 255, 255).on_truecolor(244, 67, 54)), // Red
        x if x >= 400 => format!("{} {}", response_code.truecolor(244, 67, 54), spaced_response_text.truecolor(255, 255, 255).on_truecolor(244, 67, 54)), // Red
        x if x >= 300 => format!("{} {}", response_code.truecolor(255, 152, 0), spaced_response_text.truecolor(255, 255, 255).on_truecolor(255, 152, 0)), // Yellow
        x if x >= 200 => format!("{} {}", response_code.truecolor(76, 175, 80), spaced_response_text.truecolor(255, 255, 255).on_truecolor(76, 175, 80)), // Green
        _ => format!("{} {}", response_code, spaced_response_text.truecolor(255, 255, 255).on_truecolor(71, 71, 71))
    }



}




fn color_request_method(method: &String) -> ColoredString {

    let spaced_method: String = format!(" {} ", method);

    match method.as_str() {
        "REGISTER" => spaced_method.truecolor(255, 255, 255).on_truecolor(177, 44, 201), // Magenta
        "INVITE" => spaced_method.truecolor(255, 255, 255).on_truecolor(26, 115, 232), // Blue
        "UPDATE" => spaced_method.truecolor(255, 255, 255).on_truecolor(0, 184, 204), // Cyan
        "CANCEL" => spaced_method.truecolor(255, 255, 255).on_truecolor(244, 67, 54), // Red
        "BYE" => spaced_method.truecolor(255, 255, 255).on_truecolor(255, 152, 0), // Yellow
        _ => spaced_method.truecolor(255, 255, 255).on_truecolor(71, 71, 71) // Gray
    }

}




fn parse_to_net(ipv4: &String) -> Ipv4Net {

    return match ipv4.parse() {
        Ok(ip) => ip,
        Err(_e) => {

            let inputip: Ipv4Addr = match ipv4.parse() {
                Ok(ip) => ip,
                Err(_e) => {
                    _ = writeln!(io::stderr(), "[Error] Unable to parse given IP '{}'", ipv4);
                    std::process::exit(1);
                }
            };

            Ipv4Net::new(inputip, 32).unwrap() // Could this be unsafe, theoretically not?

        }

    };
}




fn numbermachtes(packet_number: &String, compare_number: &str) -> bool {

    let mut packet: String = packet_number.to_string(); // Number as its found in the packet

    // Removes C60 in packet-Number if you don't search for one
    if let Some(c60idx) = packet.to_lowercase().find("c60") {
        if !compare_number.to_lowercase().contains("c60") {   
            packet = format!("{}{}", &packet[..c60idx], &packet[c60idx+9..]);
        }
    }

    return packet.to_lowercase().contains(&compare_number.to_lowercase());

}




fn to_headercase(header: String) -> String {

    let parts: Vec<&str> = header.split("-").collect();
    let mut reformatted: Vec<String> = Vec::new();

    for p in parts {

        if p.to_lowercase() == "id" {
            reformatted.push("ID".to_string());
        }else if p.to_lowercase() == "cseq" {
            reformatted.push("CSeq".to_string());
        }else{
            if p.len() >= 2 {
                reformatted.push(p[..1].to_uppercase().to_string() + &p[1..].to_lowercase().to_string());
            }else {
                reformatted.push(p.to_uppercase().to_string());
            }
        }
    }

    reformatted.join("-")
}




fn color_print_packet(args: &Args, packet_obj: &mut Packet, packet_buffer: &Vec<String>) {

    // COLOR LIST

    // I previously tried using the default Terminal Colors, that approach is conveniant, but limited for future change.
    // Now i switched to manually using Truecolor RGB codes. This could probably be solved easier in some other way in the future
    // Here's the List of the Color palette:

    // |             | WHITE         | DARK       | BLACK      | RED           | GREEN         | YELLOW       | BLUE         | MAGENTA      | CYAN        | LIGHT         |
    // |-------------|---------------|------------|------------|---------------|---------------|--------------|--------------|--------------|-------------|---------------|
    // | Color       | 235, 235, 235 | 18, 18, 18 | 71, 71, 71 | 244, 67, 54   | 76, 175, 80   | 255, 152, 0  | 26, 115, 232 | 177, 44, 201 | 0, 184, 204 | 235, 235, 235 |
    // | Color Light | 255, 255, 255 | 18, 18, 18 | 92, 92, 92 | 247, 110, 100 | 113, 193, 116 | 255, 173, 51 | 69, 142, 237 | 193, 71, 215 | 0, 220, 245 | 255, 255, 255 |
    // | Color Dark  | 214, 214, 214 | 18, 18, 18 | 51, 51, 51 | 230, 40, 33   | 68, 156, 71   | 224, 135, 0  | 20, 100, 204 | 148, 37, 167 | 0, 147, 163 | 214, 214, 214 |

    // Here is a more readable version using Coolors:

    // Color: https://coolors.co/ebebeb-121212-474747-f44336-4caf50-ff9800-1a73e8-b12cc9-00b8cc-ebebeb
    // Color Light: https://coolors.co/ffffff-121212-5c5c5c-f76e64-71c174-ffad33-458eed-c147d7-00dcf5-ffffff
    // Color Dark: https://coolors.co/d6d6d6-121212-333333-e62821-449c47-e08700-1464cc-9425a7-0093a3-d6d6d6 


    // Don't print filtered Packages
    if !packet_obj.filter_out {

        // ### Print RAW
        if args.print_raw {
            
            if args.print_reduced {
                _ = writeln!(io::stdout(), "{}", packet_buffer[0]);

            }else{
                for pbl in packet_buffer {
                    if args.nosdp {
                        if &pbl[1..2] != "=" {
                            _ = writeln!(io::stdout(), "{}", pbl)
                        }
                    }else{
                        _ = writeln!(io::stdout(), "{}", pbl)
                    }
                }
                _ = write!(io::stdout(), "\n");
            }

        
        }else{

            // ### Print Fancy

            // Print Packet info
            let mut _pinfo: String = String::new();

            let mut date = "".to_string().truecolor(69, 142, 237);
            if packet_obj.time.date() != NaiveDate::from_ymd_opt(1970, 1, 1).unwrap() {
                date = packet_obj.time.format("%Y-%m-%d ").to_string().truecolor(69, 142, 237);
            }

            if packet_obj.outgoing {
                _pinfo = format!("({}{}) {}:{} -->> {}:{} ({} bytes)", date, packet_obj.time.format("%H:%M:%S.%3f").to_string().truecolor(69, 142, 237), packet_obj.srcip.to_string().truecolor(113, 193, 116), packet_obj.srcport.to_string().truecolor(76, 175, 80), packet_obj.dstip.to_string().truecolor(247, 110, 100), packet_obj.dstport.to_string().truecolor(244, 67, 54), packet_obj.payload_size);
            }else{
                _pinfo = format!("({}{}) {}:{} <<-- {}:{} ({} bytes)", date, packet_obj.time.format("%H:%M:%S.%3f").to_string().truecolor(69, 142, 237), packet_obj.dstip.to_string().truecolor(113, 193, 116), packet_obj.dstport.to_string().truecolor(76, 175, 80), packet_obj.srcip.to_string().truecolor(247, 110, 100), packet_obj.srcport.to_string().truecolor(244, 67, 54), packet_obj.payload_size);
            }
            _ = writeln!(io::stdout(), "{}", _pinfo);


            
            if !packet_obj.error {

                if !args.print_reduced {

                    // Print Status Line
                    let mut _pstatus: String = String::new();
                    if packet_obj.isresponse {
                        _pstatus = format!("{} {}", packet_obj.sip_version, color_response_method(&packet_obj.response_code, &packet_obj.response_text)); 
                    }else {
                        _pstatus = format!("{} {} {}", color_request_method(&packet_obj.sip_method), packet_obj.request_uri, packet_obj.sip_version);
                    }
                    _ = writeln!(io::stdout(), "{}", _pstatus);
                    
                    // Print SIP
                    if packet_obj.sip.len() > 0 {
                        for (key, value) in &packet_obj.sip {

                            // Search for signs of a multiple same-named Headers (see end of parse_packet for context)
                            for valp in value.clone().split(" ¶ ") {
                            
                                // ### CALL-ID ###
                                if key == "Call-ID" {
                                    let atidx = valp.find("@").unwrap_or(valp.len());
                                    _ = writeln!(io::stdout(), "{}: {}{}", key.truecolor(255, 255, 255), valp[..atidx].to_string().truecolor(177, 44, 201), valp[atidx..].to_string());
                                
                                // ### FROM / TO ###
                                }else if key == "From" || key == "To" || key == "P-Asserted-Identity" {
                                    // Try to narrow down the string to the actual number, not the whole URI
                                    let startidx = valp.find("sip:").and_then(|x| Some(x+4)).unwrap_or(0);
                                    let mut endidx = valp.find("@").unwrap_or( valp.find(">").unwrap_or(valp.len()));
                                    if endidx > valp.find(";").unwrap_or(valp.len()) {
                                        endidx = valp.find(";").unwrap_or(valp.len())
                                    }
                                    // Check if number contains C60 and is inside number
                                    if let Some(c60idx) = valp.to_lowercase().find("c60").filter(|x| x > &startidx && x < &endidx) {
                                        // The lighter yellow color used for the C60 is not following the Table, i used: #FFC670 / 255, 198, 112
                                        _ = writeln!(io::stdout(), "{}: {}{}{}{}{}", key.truecolor(255, 255, 255), valp[..startidx].to_string(), valp[startidx..c60idx].to_string().truecolor(255, 152, 0), valp[c60idx..c60idx+9].to_string().truecolor(255, 198, 112), valp[c60idx+9..endidx].to_string().truecolor(255, 152, 0), valp[endidx..].to_string());
                                    }else{
                                        _ = writeln!(io::stdout(), "{}: {}{}{}", key.truecolor(255, 255, 255), valp[..startidx].to_string(), valp[startidx..endidx].to_string().truecolor(255, 152, 0), valp[endidx..].to_string());
                                    }

                                    
                                // ### CSEQ ###
                                }else if key == "CSeq" {
                                    let slice = valp.split_at(valp.find(" ").and_then(|x| Some(x+1)).unwrap_or(0));
                                    _ = writeln!(io::stdout(), "{}: {}{}", key.truecolor(255, 255, 255), slice.0, slice.1.to_string().truecolor(26, 115, 232));
                                    
                                // ### Contact ###
                                }else if key == "Contact" {
                                    let startidx = valp.find("@").and_then(|x| Some(x+1)).unwrap_or(valp.find(":").and_then(|x| Some(x+1)).unwrap_or(0));

                                    let semicolon = valp.find(";").unwrap_or(valp.len());
                                    let tribracket = valp.find(">").unwrap_or(valp.len());

                                    if semicolon == tribracket {
                                        _ = writeln!(io::stdout(), "{}: {}", key.truecolor(255, 255, 255), valp);
                                    }else if semicolon < tribracket{
                                        _ = writeln!(io::stdout(), "{}: {}{}{}", key.truecolor(255, 255, 255), valp[..startidx].to_string(), valp[startidx..semicolon].to_string().truecolor(0, 220, 245), valp[semicolon..].to_string());
                                    }else{
                                        _ = writeln!(io::stdout(), "{}: {}{}{}", key.truecolor(255, 255, 255), valp[..startidx].to_string(), valp[startidx..tribracket].to_string().truecolor(0, 220, 245), valp[tribracket..].to_string());
                                    }

                                // ### REASON ###
                                }else if key == "Reason" {
                                    if packet_obj.response_code.parse().unwrap_or(-1) >= 400 {
                                        _ = writeln!(io::stdout(), "{}: {}", key.truecolor(255, 255, 255), valp.truecolor(244, 67, 54).to_string());
                                    }else {
                                        _ = writeln!(io::stdout(), "{}: {}", key.truecolor(255, 255, 255), valp);
                                    }
                                
                                }else{

                                    _ = writeln!(io::stdout(), "{}: {}", key.truecolor(255, 255, 255), valp);

                                }

                            }

                        }
                        _ = write!(io::stdout(), "\n");
                    }
                    

                    // Print SDP
                    if packet_obj.sdp.len() > 0 && !args.nosdp {
                        for value in &packet_obj.sdp {
                            
                            // ### RTP IP ###
                            if value.starts_with("c=") {
                                let ipidx = value.find("IP4 ").and_then(|x| Some(x+4)).unwrap_or(value.find("=").and_then(|x| Some(x+1)).unwrap_or(0));
                                _ = writeln!(io::stdout(), "{}{}", value[..ipidx].to_string(), value[ipidx..].to_string().truecolor(0, 220, 245));
                                
                            // ### RTP Codecs ###
                            }else if value.starts_with("a=rtpmap:") {
                                let slidx = value.find("/").unwrap_or(value.len());
                                _ = writeln!(io::stdout(), "{}{}{}", value[..9].to_string(), value[9..slidx].to_string().truecolor(76, 175, 80), value[slidx..].to_string());
                                
                            }else{
                                _ = writeln!(io::stdout(), "{}", value);
                            }
                        }
                        _ = write!(io::stdout(), "\n");
                    }
                    

                    // Other Lines?
                    if packet_obj.other.len() > 0 {
                        for value in &packet_obj.other {
                            _ = writeln!(io::stdout(), "{}", value.dimmed())
                        }
                        _ = writeln!(io::stderr(), "[WARNING] This Packet contained the above Lines which do not follow the 'Header: Value' or 'a=sdpvalue' structure\n");
                    }

                    // println!("---");
                    
                }else {

                    // ### Print Fancy Reduced ###

                    // Print Status Line
                    let mut _pstatus: String = String::new();

                    // From
                    let mut c_from: String = packet_obj.sip.get("From").unwrap_or(&_pstatus).to_string();
                    let startidx = c_from.find("sip:").and_then(|x| Some(x+4)).unwrap_or(0);
                    let mut endidx = c_from.find("@").unwrap_or( c_from.find(">").unwrap_or(c_from.len()));
                    if endidx > c_from.find(";").unwrap_or(c_from.len()) {
                        endidx = c_from.find(";").unwrap_or(c_from.len())
                    }
                    c_from = c_from[startidx..endidx].to_string();

                    // To
                    let mut c_to: String = packet_obj.sip.get("To").unwrap_or(&_pstatus).to_string();
                    let startidx = c_to.find("sip:").and_then(|x| Some(x+4)).unwrap_or(0);
                    let mut endidx = c_to.find("@").unwrap_or( c_to.find(">").unwrap_or(c_to.len()));
                    if endidx > c_to.find(";").unwrap_or(c_to.len()) {
                        endidx = c_to.find(";").unwrap_or(c_to.len())
                    }
                    c_to = c_to[startidx..endidx].to_string();

                    // CSeq
                    let mut c_cseq: String = packet_obj.sip.get("CSeq").unwrap_or(&_pstatus).to_string();
                    c_cseq = format!("(CSeq: {})", c_cseq.split_at(c_cseq.find(" ").and_then(|x| Some(x+1)).unwrap_or(0)).1.to_string()).dimmed().to_string();


                    if packet_obj.isresponse {
                        _pstatus = format!("{} {} | From: {} To: {}", color_response_method(&packet_obj.response_code, &packet_obj.response_text), c_cseq, c_from, c_to); 
                    }else {
                        _pstatus = format!("{} {} | From: {} To: {}", color_request_method(&packet_obj.sip_method), c_cseq, c_from, c_to);
                    }
                    _ = writeln!(io::stdout(), "{}\n", _pstatus);

                }


            }else{
                _ = writeln!(io::stderr(), "  [Error] {}\n", packet_obj.error_text)
            }


        }

    }

}




fn filter_packet(args: &Args, packet_obj: &mut Packet, packet_buffer: &Vec<String>, negated_filters: &HashSet<&str>) {

    packet_obj.filter_out = true;


    let mut filter_results: IndexMap<String, bool> = IndexMap::new();



    // ### NUMBER ### 
    if args.number.is_some() || args.from.is_some() || args.to.is_some() {

        let from = match packet_obj.sip.get("From") {
            Some(from) => {
                
                // Try to narrow down the string to the actual number, not the whole URI
                let startidx = from.find(":").and_then(|x| Some(x+1)).unwrap_or(0);
                let endidx = from.find("@").unwrap_or( from.find(">").unwrap_or(from.len()));

                from[startidx..endidx].to_string().to_lowercase()
            },
            None => "".to_string()
        };
        
        let to = match packet_obj.sip.get("To") {
            Some(to) => {
                
                // Try to narrow down the string to the actual number, not the whole URI
                let startidx = to.find(":").and_then(|x| Some(x+1)).unwrap_or(0); // Adds 1 if is_some
                let endidx = to.find("@").unwrap_or( to.find(">").unwrap_or(to.len()));

                to[startidx..endidx].to_string().to_lowercase()
            },
            None => "".to_string()
        };

        // Debug:
        // println!("From: {}", from);
        // println!("To: {}", to);


        // --from
        if args.from.is_some() {
            if args.from.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && numbermachtes(&from, &arg) ) {
                filter_results.insert("from".to_string(), true);
            }else {
                filter_results.insert("from".to_string(), false);
            }
        } 
        
        // --to
        if args.to.is_some() {
            if args.to.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && numbermachtes(&to, &arg) ) {
                filter_results.insert("to".to_string(), true);
            }else {
                filter_results.insert("to".to_string(), false);
            }
        } 
        
        // --number
        if args.number.is_some() {
            if args.number.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && (numbermachtes(&from, &arg) || numbermachtes(&to, &arg.to_lowercase())) ) {
                filter_results.insert("number".to_string(), true);
            }else {
                filter_results.insert("number".to_string(), false);
            }
        }
        
    }



    // ### IP ### 
    if args.ip.is_some() || args.srcip.is_some() || args.dstip.is_some() {

        if args.srcip.is_some() {
            if args.srcip.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && parse_to_net(arg).contains(&packet_obj.srcip) ) {
                filter_results.insert("srcip".to_string(), true);
            }else {
                filter_results.insert("srcip".to_string(), false);
            }
        }
        
        if args.dstip.is_some() {
            if args.dstip.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && parse_to_net(arg).contains(&packet_obj.dstip) ) {
                filter_results.insert("dstip".to_string(), true);
            }else {
                filter_results.insert("dstip".to_string(), false);
            }
        }
        
        if args.ip.is_some() && !args.srcip.is_some() && !args.dstip.is_some() {
            if args.ip.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && parse_to_net(arg).contains(&packet_obj.srcip) || parse_to_net(arg).contains(&packet_obj.dstip) ) {
                filter_results.insert("ip".to_string(), true);
            }else {
                filter_results.insert("ip".to_string(), false);
            }
        }
    }



    // ### PORT ### 
    if args.port.is_some() || args.srcport.is_some() || args.dstport.is_some() {

        if args.srcport.is_some() {
            if args.srcport.as_ref().unwrap().into_iter().any(|arg| &packet_obj.srcport == arg ) {
                filter_results.insert("srcport".to_string(), true);
            }else {
                filter_results.insert("srcport".to_string(), false);
            }
        }

        if args.dstport.is_some() {
            if args.dstport.as_ref().unwrap().into_iter().any(|arg| &packet_obj.dstport == arg ) {
                filter_results.insert("srcport".to_string(), true);
            }else {
                filter_results.insert("srcport".to_string(), false);
            }
        }
        
        if args.port.is_some() {
            if args.port.as_ref().unwrap().into_iter().any(|arg| &packet_obj.srcport == arg || &packet_obj.dstport == arg ) {
                filter_results.insert("port".to_string(), true);
            }else {
                filter_results.insert("port".to_string(), false);
            }
        }

    }



    // ### INTERNAL ### 
    if !args.internal && (packet_obj.srcip.is_private() && packet_obj.dstip.is_private()) {
        filter_results.insert("internal".to_string(), false);
    }else{
        filter_results.insert("internal".to_string(), true);
    }



    // ### CALL-ID ### 
    if args.call_id.is_some() {

        let empty = "".to_string();
        let cid = packet_obj.sip.get("Call-ID").unwrap_or(&empty);

        if args.call_id.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && cid.contains(arg)) {
            filter_results.insert("call_id".to_string(), true);
        }else{
            filter_results.insert("call_id".to_string(), false);
        }

    }



    // ### SIP-METHOD / RES-TEXT ### 
    if args.method.is_some() {
        if args.method.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && (packet_obj.sip_method.to_uppercase().contains(&arg.to_uppercase()) || packet_obj.response_text.to_uppercase().contains(&arg.to_uppercase())) ) {
            filter_results.insert("method".to_string(), true);
        }else {
            filter_results.insert("method".to_string(), false);
        }
    }



    // ### STATUS-CODE ### 
    if args.status_code.is_some() {
        if args.status_code.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && packet_obj.response_code.starts_with(arg)) {
            filter_results.insert("status_code".to_string(), true);
        }else {
            filter_results.insert("status_code".to_string(), false);
        }
    }



    // ### CSEQ / METHOD ### 
    if args.cseq_method.is_some() {

        let empty = "".to_string();
        let cseq = packet_obj.sip.get("CSeq").unwrap_or(&empty).to_lowercase();

        if !cseq.is_empty() {
            if args.cseq_method.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && cseq.contains(&arg.to_lowercase()) ) {
                filter_results.insert("cseq_method".to_string(), true);
            }else {
                filter_results.insert("cseq_method".to_string(), false);

            }
        }
    }



    // ### STRING ### 
    if args.string.is_some() {
        if args.string.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && packet_buffer.into_iter().any(|line| line.to_lowercase().contains(&arg.to_lowercase())) ) {
            filter_results.insert("string".to_string(), true);
        }else {
            filter_results.insert("string".to_string(), false);
        }
    }



    // ### REGEX ### 
    if args.regex.is_some() {

        if !args.regex.as_ref().unwrap().trim().is_empty() {
            
            match Regex::new(args.regex.as_ref().unwrap()) {
                Ok(rex) => {
                    if packet_buffer.into_iter().any(|line| rex.is_match(line)) {
                        filter_results.insert("regex".to_string(), true);
                    }else{
                        filter_results.insert("regex".to_string(), false);
                    }
                },
                Err(_e) => {
                    _ = writeln!(io::stderr(), "[Error] Unable to parse Regular Expression");
                    std::process::exit(1);
                }
            }

        }else {
            filter_results.insert("regex".to_string(), false);
        }
    }



    // ### TIME ###
    if args.time.is_some() {

        let timevec = args.time.as_ref().unwrap();

        let errstr_nl = "\n        ".to_string();
        let errstr_format = "A Time has to be formatted in one of the following Ways: '13', '13:07' or '13:07:21'. \n        (Zero-padded pairs of two digits separated by colons)".to_string();

        let mut fromtime: Option<NaiveTime> = None;
        let mut totime: Option<NaiveTime> = None;

        if timevec.len() == 2 {

            // Parse the two time strings
            for (timeidx, timestr) in timevec.into_iter().enumerate() {

                if timestr.trim().len() != 0 {
                    
                    let split:Split<&str> = timestr.split(":");
                    let splitlen: usize = split.clone().count();

                    if splitlen < 1 || splitlen > 3 {
                        _ = writeln!(io::stderr(), "[Error] {}", errstr_format);
                        std::process::exit(1);
                    }

                    let mut hour: u32 = 0;
                    let mut minute: u32 = 0;
                    let mut second: u32 = 0;

                    // Evaluate every hour, minute an second 
                    for (idx, sp) in split.enumerate() {

                        if sp.len() != 2 {
                            _ = writeln!(io::stderr(), "[Error] {}", errstr_format);
                            std::process::exit(1);
                        }

                        match idx {
                            0 => {
                                hour = sp.parse().unwrap_or(99);
                            },
                            1 => {
                                minute = sp.parse().unwrap_or(99);
                            }, 
                            2 => {
                                second = sp.parse().unwrap_or(99);
                            }
                            _ => {}
                        }
                    }

                    if timeidx == 0 {
                        fromtime = NaiveTime::from_hms_opt(hour, minute, second);
                            
                        if fromtime.is_none() {
                            _ = writeln!(io::stderr(), "[Error] Unable to parse Time '{}'.{}{}", timevec.join("_"), errstr_nl, errstr_format);
                            std::process::exit(1);
                        }

                    }else if timeidx == 1 {
                        totime = NaiveTime::from_hms_opt(hour, minute, second);
                            
                        if totime.is_none() {
                            _ = writeln!(io::stderr(), "[Error] Unable to parse Time '{}'.{}{}", timevec.join("_"), errstr_nl, errstr_format);
                            std::process::exit(1);
                        }
                    }
                }
            }

        }else{
            _ = writeln!(io::stderr(), "[Error] To pass a Time Filter two values are needed, separated by an underscore (_). Like '-t 12:48_13:25' or '-t _15:37'. \n        Not providing a value on one side filters from/to the beginning/end of the file to/from the given time.{}{}", errstr_nl, errstr_format);
            std::process::exit(1);
        }


        if fromtime.is_some() && totime.is_some() {

            if packet_obj.time.time() >= fromtime.unwrap() && packet_obj.time.time() <= totime.unwrap(){
                filter_results.insert("time".to_string(), true);
            }else{
                filter_results.insert("time".to_string(), false);
            }
            
        } else if fromtime.is_some() && totime.is_none() {
            
            if packet_obj.time.time() >= fromtime.unwrap() {
                filter_results.insert("time".to_string(), true);
            }else {
                filter_results.insert("time".to_string(), false);
            }
            
        } else if fromtime.is_none() && totime.is_some() {
            
            if packet_obj.time.time() <= totime.unwrap() {
                filter_results.insert("time".to_string(), true);
            }else{
                filter_results.insert("time".to_string(), false);
            }

        } else {
            _ = writeln!(io::stderr(), "[Error] To pass a Time Filter two values are needed, separated by an underscore (_). Like '-t 12:48_13:25' or '-t _15:37'. \n        Not providing a value on one side filters from/to the beginning/end of the file to/from the given time.{}{}", errstr_nl, errstr_format);
            std::process::exit(1);
        }

    }



    // ### REQUEST ### 
    if args.request {
        if !packet_obj.isresponse{
            filter_results.insert("request".to_string(), true);
        }else {
            filter_results.insert("request".to_string(), false);
        }
    }



    // ### RESPONSE ### 
    if args.response {
        if packet_obj.isresponse{
            filter_results.insert("response".to_string(), true);
        }else {
            filter_results.insert("response".to_string(), false);
        }
    }



    // ### SDP ### 
    if args.hassdp {
        if packet_obj.sdp.len() > 0 {
            filter_results.insert("sdp".to_string(), true);
        }else {
            filter_results.insert("sdp".to_string(), false);
        }
    }


    for (filter_name, filter_result) in filter_results.iter_mut() {
        if negated_filters.contains(filter_name.as_str()) {
            *filter_result = !*filter_result;
        }
    }


    // ### Evalutes Package treatment based on Filter joining Method ###
    if !args.or_filter {
        // AND
        if filter_results.values().into_iter().all(|x| *x) { 
            packet_obj.filter_out = false; 
        }
    }else{
        // OR
        if filter_results.values().into_iter().any(|x| *x) {
            packet_obj.filter_out = false;
        }
    }

    // // DEBUG
    // print!("┌= FILTER =-\n");s
    // for x in &filter_results {
    //     println!("| -> {:?}", x);
    // }
        
}




fn parse_packet(packet_buffer: &mut Vec<String>, packet_obj: &mut Packet, date: NaiveDate) {

    for (idx, line) in packet_buffer.iter().enumerate(){
        
        match idx {
            // PACKET INFO
            0 => {
                
                if line.starts_with("("){

                    // Split the line into sections by spaces 
                    let info: Vec<&str> = line.split(" ").into_iter().collect();
                    
                    // Check if it has enough Elements
                    if info.len() >= 9 {

                        // DATE-TIME : Parse current Time and update the Time in the initialized Object if Ok
                        let parsedtime = match NaiveTime::parse_from_str(&info.get(0).unwrap_or(&"(00:00:00.00)")[1..12], "%H:%M:%S%.f") {
                            Ok(time) => NaiveDateTime::new(date, time),
                            Err(_e) => {
                                packet_obj.error = true;
                                packet_obj.error_text = "Unable to parse Time".to_string();
                                packet_obj.time
                            },
                        };
                        packet_obj.time = parsedtime;
            
            
                        // DIR : Parses the direction of the Packet
                        let arrow: &str = match info.get(4) {
                            Some(direction) => direction,
                            None => {
                                packet_obj.error = true;
                                packet_obj.error_text = "The Direction was guessed".to_string();
                                "->"
                            }
                        };
                        packet_obj.outgoing = arrow == "->";
                        
                        
                        // HOST IP:PORT
                        let host_one_str: &&str = &info.get(3).unwrap_or(&"<0.0.0.0:0>");
                        let host_one_unwrapped = if host_one_str.len() >= 2 {
                            &host_one_str[1..host_one_str.len()-1]
                        } else {
                            "0.0.0.0:0"
                        };
                        let host_one_split: Vec<&str> = host_one_unwrapped.split(':').collect();
                        
                        let host_two_str: &&str = &info.get(8).unwrap_or(&"<0.0.0.0:0>");
                        let host_two_unwrapped = if host_two_str.len() >= 2 {
                            &host_two_str[1..host_two_str.len()-1]
                        } else {
                            "0.0.0.0:0"
                        };
                        let host_two_split: Vec<&str> = host_two_unwrapped.split(':').collect();
            
                        // Left Host
                        let host_one_ip: Ipv4Addr = match host_one_split.get(0).unwrap_or(&"0.0.0.0").parse() {
                            Ok(ip) => ip,
                            Err(_e) => Ipv4Addr::new(0, 0, 0, 0),
                        };

                        let host_one_port: u16 = match host_one_split.get(1).unwrap_or(&"0").parse() {
                            Ok(port) => port,
                            Err(_e) => 0,
                        };

                        // Right Host
                        let host_two_ip: Ipv4Addr = match host_two_split.get(0).unwrap_or(&"0.0.0.0").parse() {
                            Ok(ip) => ip,
                            Err(_e) => Ipv4Addr::new(0, 0, 0, 0),
                        };
            
                        let host_two_port: u16 = match host_two_split.get(1).unwrap_or(&"0").parse() {
                            Ok(port) => port,
                            Err(_e) => 0,
                        };
                        
                        // Set direction
                        if packet_obj.outgoing {
                            packet_obj.srcip = host_one_ip;
                            packet_obj.srcport = host_one_port;
                            packet_obj.dstip = host_two_ip;
                            packet_obj.dstport = host_two_port;
                        }else{
                            packet_obj.srcip = host_two_ip;
                            packet_obj.srcport = host_two_port;
                            packet_obj.dstip = host_one_ip;
                            packet_obj.dstport = host_one_port;
                        }
            
            
                        // SIZE : Payload Size
                        let payload_size: u32 = match info.get(5).unwrap_or(&"0").parse() {
                            Ok(size) => size,
                            Err(_e) => 0,
                        };
                        packet_obj.payload_size = payload_size;
                    }
                }else{
                    packet_obj.error = true;
                    packet_obj.error_text = "First line of packet should start with '(' and contain Packet information".to_string();
                }

            },
            
            // STATUS LINE
            1 => {
                // The first Line should be the Status line

                let statusline: &Vec<&str> = &line.split(" ").collect();

                // Checks if there are enough Element
                if statusline.len() >= 3 {

                    if statusline.get(0).unwrap_or(&"").trim().starts_with("SIP/"){
                        // Packet is a SIP Response
                        packet_obj.isresponse = true;
                        packet_obj.sip_version = statusline.get(0).unwrap_or(&"").trim().to_string();
                        packet_obj.response_code = statusline.get(1).unwrap_or(&"").trim().to_string();
                        packet_obj.response_text = statusline.get(2..statusline.len()).unwrap_or(&[""]).join(" ").trim().to_string();
                        
                    }else if SIP_METHODS.iter().any(|s| statusline.get(0).unwrap_or(&"").trim().to_uppercase().starts_with(*s)) {
                        // Packet is a SIP Request
                        packet_obj.isresponse = false;
                        packet_obj.sip_method = statusline.get(0).unwrap_or(&"").trim().to_string();
                        packet_obj.request_uri = statusline.get(1).unwrap_or(&"").trim().to_string();
                        packet_obj.sip_version = statusline.get(2..statusline.len()-1).unwrap_or(&[""]).join(" ").trim().to_string();
                        
                    }else{
                        packet_obj.error = true;
                        packet_obj.error_text = "Second line of packet should be the SIP Status Line for Requests or Responses".to_string();
                    }
                }
            },

            // BODY
            _ => {

                // SDP
                if &line[1..2] == "=" {
                    
                    packet_obj.sdp.push(line.to_string());
                    
                }else{
                    // SIP
                    match line.find(":") {
                        Some(splitindex) => {
                            
                            let slices = line.split_at(splitindex);
                            
                            let key = to_headercase(slices.0[..slices.0.len()].trim().to_string().to_lowercase());
                            let mut value = slices.1[1..].trim().to_string();

                            // WORKAROUND
                            // Turns out duplicate Headers can exist... Check for that. Since i don't want to rework
                            // everything and i'm using a IndexMap i'll combine the values with a delimiting
                            // character (¶) that is (i think) not used in any Header values in this form to 
                            // distinguish between values. The printing function then seperates the Values again.
                            if let Some(ov) = packet_obj.sip.get(&key) {
                                value = format!("{} ¶ {}", ov, value);
                            }

                            packet_obj.sip.insert(key, value);
                            
                        },
                        None => { 
                            packet_obj.other.push(line.to_string());
                        }
                    }
                }

            }
        }

    }

}




fn handle_log_line(args: &Args, packet_buffer: &mut Vec<String>, mut packet_obj: &mut Packet, line: &String, date: NaiveDate, negated_filters: &HashSet<&str>){
    
    if line.trim().starts_with("(") {

        // Clear the buffer if the current and last line start with "("
        if packet_buffer.last().is_some_and(|x| x.starts_with("(")) {
            packet_buffer.clear();
        }

        // if the current line starts with "(" and there are lines waiting in the buffer, filter, color and print them
        if packet_buffer.len() > 1 {

            let empty = "".to_string();
            let part = packet_buffer.first().unwrap_or(&empty).split(" ").nth(2).unwrap_or("");

            if part == "in" || part == "out" {

                // Reset the Packet Object before reuse
                packet_obj.reset();
                
                // Do the actual work
                parse_packet(packet_buffer, &mut packet_obj, date);
                filter_packet(args, &mut packet_obj, packet_buffer, negated_filters);
                color_print_packet(args, &mut packet_obj, packet_buffer);
            }

            packet_buffer.clear();
        }
    }
    
    // Add current line to the Buffer if its not empty
    if line.trim().len() > 2 {
        packet_buffer.push(line.clone());
    }
    
}




fn main() {


    // let matches = Args::command().get_matches();
    // let mut negated_filters: HashSet<&str> = HashSet::new();

    // println!("matches: {:?}", matches);

    // if let Some(not_indices) = matches.indices_of("not_filter") {
    //     if let Some(not_index) = not_indices.into_iter().next() {


    //         let filter_ids = [
    //             "number", "from", "to", "ip", "srcip", "dstip", "port", "srcport", "dstport",
    //             "call_id", "method", "status_code", "cseq_method", "string", "regex", "time",
    //             "request", "response", "internal", "hassdp"
    //         ];

    //         for id in filter_ids {
    //             if let Some(indices) = matches.indices_of(id) {
    //                 if let Some(first_index) = indices.into_iter().next() {
    //                     if first_index > not_index {
    //                         negated_filters.insert(id);
    //                     }
    //                 }
    //             }
    //         }
    //     }
    // }


    let matches = Args::command().get_matches();
    let mut negated_filters: HashSet<&str> = HashSet::new();

    // First check if not_filter is true
    if matches.get_flag("not_filter") {
        // Get the raw command-line arguments from the "Args" entry
        if let Some(args_entry) = matches.try_get_raw("Args").ok().flatten() {
            let raw_args: Vec<&str> = args_entry.map(|s| s.to_str().unwrap()).collect();

            println!("\n\nraw_args: {:?}", raw_args);
            
            // Find the position of "not_filter" in the raw arguments
            if let Some(not_pos) = raw_args.iter().position(|&arg| arg == "not_filter") {
                let filter_ids = [
                    "number", "from", "to", "ip", "srcip", "dstip", "port", "srcport", "dstport",
                    "call_id", "method", "status_code", "cseq_method", "string", "regex", "time",
                    "request", "response", "internal", "hassdp", "nosdp"
                ];

                // Check which filter IDs appear in raw_args after not_filter
                for &id in &filter_ids {
                    if let Some(id_pos) = raw_args.iter().position(|&arg| arg == id) {
                        if id_pos > not_pos {
                            negated_filters.insert(id);
                        }
                    }
                }
            }
        }
    }

    let args = Args::from_arg_matches(&matches).expect("Failed to parse args");

    let mut packet_buffer: Vec<String> = Vec::new();
    let mut packet_obj: Packet = Packet::new(); 

    // Checks if a file path is provided
    match args.input_file {
        None => {
            // ### Method 1: Read stdin if there is Data ###

            // Checks if stdin is empty and terminate in case
            if atty::is(atty::Stream::Stdin){
                _ = writeln!(io::stdout(), "{} {}", "Usage:".green(), "xsip [INPUT_FILE] [OPTIONS] \nTry 'xsip -h' or 'xsip --help' for more information.");
                return;
            }

            // Read and process stdin 
            let mut line = String::new();

            let date = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();

            // Read line by line while reusing the same line var -> more efficient
            while io::stdin().lock().read_line(&mut line).is_ok_and(|x| x != 0) {

                line = line.strip_suffix("\r\n")
                            .or(line.strip_suffix("\n"))
                            .unwrap_or(&line).to_string();

                handle_log_line(&args, &mut packet_buffer, &mut packet_obj, &line, date, &negated_filters);

                line.clear();
            }

        },

        Some(ref path) => {
            // Check if file path and stdin are provided an warn the user
            if !atty::is(atty::Stream::Stdin){
                _ = writeln!(io::stderr(), "[WARNING] Avoid passing xsip a file path and pipeing something into it! Continuing with the Filepath...");
            }

            // Check if file path exists
            if path.exists() {

                // Checks if it should enable follow mode 
                if !args.follow {
                    // ### Method 2: Read whole file normally ###

                    if path.file_name().unwrap_or(OsStr::new("")).to_string_lossy().contains(".gz") {

                        _ = writeln!(io::stdout(), "[Info] Found compressed file, using GzDecoder...\n");

                        // Compressed File
                        if let Ok(file) = fs::File::open(path) {
                            
                            let mut reader = BufReader::new(GzDecoder::new(file));
                            let mut line = String::new();

                            // Get file creation Time if possible, otherwise return 1970-01-01
                            let file_date = fs::metadata(path).ok()
                                .and_then(|metadata| metadata.modified().ok())
                                .map(|time| Utc.timestamp_opt(time.duration_since(std::time::UNIX_EPOCH).unwrap_or(std::time::Duration::ZERO).as_secs() as i64, 0).unwrap())
                                .map(|datetime| datetime.date_naive())
                                .unwrap_or_else(|| NaiveDate::from_ymd_opt(1970, 1, 1).unwrap());

                            
                            // Read line by line while reusing the same line var -> more efficient
                            while reader.read_line(&mut line)
                                        .or_else(|e| {
                                            if e.kind() == ErrorKind::InvalidData {
                                                line = "".to_string();
                                                return Ok(1)
                                            }else {
                                                return Err(e);
                                            }
                                        })
                                        .is_ok_and(|x| x != 0) 
                            {

                                line = line.strip_suffix("\r\n")
                                            .or(line.strip_suffix("\n"))
                                            .unwrap_or(&line).to_string();

                                handle_log_line(&args, &mut packet_buffer, &mut packet_obj, &line, file_date, &negated_filters);

                                line.clear();
                            }

                        }else {
                            _ = writeln!(io::stderr(), "[Error] Unable to open file '{}'", path.display());
                        }
                        
                    }else{

                        // Uncompressed File
                        if let Ok(file) = fs::File::open(path) {

                            let mut reader: Box<dyn BufRead> = Box::new(BufReader::new(file));
                            let mut line = String::new();
                            
                            // Get file creation Time if possible, otherwise return 1970-01-01
                            let file_date = fs::metadata(path).ok()
                            .and_then(|metadata| metadata.modified().ok())
                            .map(|time| Utc.timestamp_opt(time.duration_since(std::time::UNIX_EPOCH).unwrap_or(std::time::Duration::ZERO).as_secs() as i64, 0).unwrap())
                            .map(|datetime| datetime.date_naive())
                            .unwrap_or_else(|| NaiveDate::from_ymd_opt(1970, 1, 1).unwrap());
                        

                            // Read line by line while reusing the same line var -> more efficient
                            while reader.read_line(&mut line)
                                        .or_else(|e| {
                                            if e.kind() == ErrorKind::InvalidData {
                                                line = "".to_string();
                                                return Ok(1)
                                            }else {
                                                return Err(e);
                                            }
                                        })
                                        .is_ok_and(|x| x != 0) 
                            {

                                line = line.strip_suffix("\r\n")
                                            .or(line.strip_suffix("\n"))
                                            .unwrap_or(&line).to_string();

                                handle_log_line(&args, &mut packet_buffer, &mut packet_obj, &line, file_date, &negated_filters);

                                line.clear();
                            }

                        }else {
                            _ = writeln!(io::stderr(), "[Error] Unable to open file '{}'", path.display());
                        }

                    }

                }else{
                    // ### Method 3: Tail file and hot reload ### 


                    // Get File
                    let mut fpos = std::fs::File::open(&path).expect("[Error] Couldn't read file");

                    // Get end of file position and save it in Atomic Int (Thread-safe; needed for Watcher Event-Handlers)
                    let pos = Arc::new(AtomicU64::new(fpos.metadata().expect("[Error] Couldn't read file length").len()));
                    
                    // Clone Path so that the watcher can have the original object
                    let eventlistenerpath: PathBuf = path.clone();
                    let watcherpath: PathBuf = path.clone();


                    // Define Watcher
                    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                        
                        match res {
                            Ok(_event) => {

                                println!("::w:: Event: {:?}", _event); // DEBUG
                                
                                match _event.kind {
                                    
                                    // If Event says that file was closed after writing, and it exists, read new characters
                                    // Using Close(Write) Event, because Data(Change) leads to race conditions with the file save mechanism
                                    EventKind::Access(AccessKind::Close(AccessMode::Write)) => {

                                        if Path::new(&eventlistenerpath).exists() {

                                            let mut f = std::fs::File::open(&eventlistenerpath).expect("[Error] Couldn't read file");
                                            
                                            let lastpos = pos.load(Ordering::SeqCst);
                                            let mut curpos = f.metadata().expect("Generic Error").len();
                                            
                                            
                                            // ignore any event that didn't change the pos (file actually not modified)
                                            if !(curpos == lastpos) {
                                                
                                                // Only proceed if file hasn't been truncated, otherwise start at the beginning
                                                if curpos < lastpos {
                                                    // println!("::w:: Size reset!"); // DEBUG
                                                    curpos = 0; 

                                                }else{
        
                                                    // Set cursor to lastpos
                                                    f.seek(std::io::SeekFrom::Start(lastpos)).expect("Generic Error");

                                                    // Read from lastpos to current end of file
                                                    let mut reader: Box<dyn BufRead> = Box::new(BufReader::new(&f));
                                                    let mut line = String::new();

                                                    // Pass every line to our filtering function
                                                    while reader.read_line(&mut line)
                                                        .or_else(|e| {
                                                            if e.kind() == ErrorKind::InvalidData {
                                                                line = "".to_string();
                                                                return Ok(1)
                                                            }else {
                                                                return Err(e);
                                                            }
                                                        })
                                                        .is_ok_and(|x| x != 0) 
                                                    {   

                                                        line = line.strip_suffix("\r\n")
                                                                    .or(line.strip_suffix("\n"))
                                                                    .unwrap_or(&line).to_string();

                                                        handle_log_line(&args, &mut packet_buffer, &mut packet_obj, &line, Local::now().date_naive(), &negated_filters);

                                                        line.clear();
                                                    }
                                                }
                                                
                                                // Update lastpos
                                                pos.store(curpos, Ordering::SeqCst);
                                                // println!("::w:: Store next pos: {:?} -> {:?}", lastpos, curpos); // DEBUG

                                            }
                                        }

                                    }

                                    _ => { }
                                }

                            }
                            Err(_error) => {
                                _ = writeln!(io::stderr(), "{_error:?}");
                                thread::sleep(time::Duration::from_millis(1000));
                            }
                        }
                    }).expect("Generic Error");



                    
                    // Start watching the given path. Calls previously defined Code on Event Trigger
                    watcher.watch(Path::new(&watcherpath), RecursiveMode::Recursive).expect("Generic Error");


                    let mut size;
                    let mut lastsize: u64 = 0;
                    let mut failcnt: u8 = 0;

                    // Continuously keep checking if the file is deleted/moved and try to rewatch the same path when it exists again
                    loop {

                        if Path::new(&watcherpath).exists() {

                            fpos = std::fs::File::open(&watcherpath).expect("[Error] Couldn't read file");
                            size = fpos.metadata().expect("[Error] Couldn't read filesize").len();
                            
                            // println!(":: Size draußen: {:?} -> {:?} ", lastsize, size); // DEBUG
                            
                            // grnti File was recreated, re-watch
                            if size < lastsize {
                                let _ = watcher.unwatch(Path::new(&watcherpath));

                                watcher.watch(Path::new(&watcherpath), RecursiveMode::Recursive).expect("Generic Error");   
                                // println!(":: Set up new watcher ") // DEBUG 
                            }

                            lastsize = size;

                            // println!(":: 5s ");
                            thread::sleep(time::Duration::from_millis(5000));

                        }else{
                            
                            // println!(":: File gone "); // DEBUG
                            thread::sleep(time::Duration::from_millis(1000));
                            failcnt += 1;

                            if failcnt >= 15 {
                                _ = writeln!(io::stdout(), "[INFO] File was moved/deleted and not recreated");
                                break; 
                            }
                        }
                    }

                }

            }else{
                _ = writeln!(io::stderr(), "[Error] This file doesn't exist: \'{}\'", path.display())
            }
        }
    }


}
