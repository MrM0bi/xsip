use chrono::{Local, NaiveDate, NaiveDateTime, NaiveTime};
use clap::Parser;
use flate2::read::GzDecoder;
use indexmap::IndexMap;
use ipnet::Ipv4Net;
use notify::event::{DataChange, ModifyKind};
extern crate atty;
use core::time;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::io::{self, BufRead, BufReader, ErrorKind};
use std::str::Split;
use std::{fs, thread, usize};
use std::io::Seek;
use std::sync::atomic::{AtomicU64, Ordering};
use notify::{EventKind, RecursiveMode, Watcher};
use std::{path::Path, sync::Arc};
use colored::*;


const SIP_METHODS: &[&str] = &["INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "PRACK", "UPDATE", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE"];


/// A command-line tool to extract, filter and Pretty-print SIP messages from Cirpack pcscf.1 and ibcf.1 log files.
/// 
/// DESCRIPTION
///   Most flags can take more than one value, these can be separated either by a colon `,` or a whitespace ` `
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
/// EXAMPLE
///   `xsip /home/log/pcscf.1 -f --ext -m REGISTER -n 0471234567;`  : Follows the file and shows all external REGISTER Requests from a specific number
///   `xsip /home/log/pcscf.1 -a 200 -q INVITE -i 151.123.321.123;` : Lists all '200 OK' Responses to previous INVITEs that where sent from/to IP 151.123.321.123
///   `xsip /home/log/pcscf.1 -s "Asterisk";`                       : Lists all Packets containing the String "Asterisk" somewhere
#[derive(Parser, Debug)]
#[command(author="Benjamin H.", version="0.2.2", about, verbatim_doc_comment, override_usage="xsip [INPUT_FILE] [OPTIONS]")]
struct Args {

    /// Path of pcscf.1 / ibcf.1 Log-file
    input_file: Option<PathBuf>,

    /// Follow growing Files; similar to `tail -f`
    /// 
    /// Hot-reloads deleted and recreated / moved files. Usefull with pcscf.1 / ibcf.1 Log-file when monitoring, since those get archived (moved) once every hour.
    #[arg(short, long, verbatim_doc_comment)]
    follow: bool,


    /// Join Filters with OR; Default: AND
    #[arg(long = "OR")]
    or_filter: bool,

    /// Exclude Packets matching the Filter
    #[arg(long = "NOT")]
    not_filter: bool,


    /// Filter Packets by number (From or To)
    #[arg(short, long, num_args=1.., value_delimiter=',')]
    number: Option<Vec<String>>,

    /// Filter Packets by From-number
    #[arg(long, num_args=1.., value_delimiter=',')]
    from: Option<Vec<String>>,

    /// Filter Packets by To-number
    #[arg(long, num_args=1.., value_delimiter=',')]
    to: Option<Vec<String>>,


    /// Filter Packets by IP (SRC or DST)
    #[arg(short, long, num_args=1.., value_delimiter=',')]
    ip: Option<Vec<String>>,

    /// Filter Packets by SRC IP
    #[arg(long, num_args=1.., value_delimiter=',')]
    srcip: Option<Vec<String>>,

    /// Filter Packets by DST IP
    #[arg(long, num_args=1.., value_delimiter=',')]
    dstip: Option<Vec<String>>,

    
    /// Filter Packets by external IPs
    #[arg(long = "ext")]
    external: bool,


    /// Filter Packets by Port (SRC or DST)
    #[arg(short, long, num_args=1.., value_delimiter=',')]
    port: Option<Vec<u16>>,

    /// Filter Packets by SRC Port
    #[arg(long, num_args=1.., value_delimiter=',')]
    srcport: Option<Vec<u16>>,

    /// Filter Packets by DST Port
    #[arg(long, num_args=1.., value_delimiter=',')]
    dstport: Option<Vec<u16>>,


    /// Filter Packets by Call-ID
    #[arg(short, long = "cid", num_args=1.., value_delimiter=',')]
    call_id: Option<Vec<String>>,

    /// Filter Packets by SIP Method or Response Text (REGISTER, INVITE, OPTIONS, etc.; Trying, Nonce, etc. )
    #[arg(short, long, num_args=1.., value_delimiter=',')]
    method: Option<Vec<String>>,

    /// Filter Packets by Response Status Code (302, 404, 5, etc.) (starting with)
    #[arg(short = 'a', long, num_args=1.., value_delimiter=',')]
    status_code: Option<Vec<String>>,

    /// Filter Packets by CSeq Sequence number or Method (2547 or REGISTER, INVITE, OPTIONS, etc.)
    #[arg(short = 'q', long = "cseq", num_args=1.., value_delimiter=',')]
    cseq_method: Option<Vec<String>>,

    /// Filter Packets by String (case-insensitive)
    #[arg(short, long = "string-search", num_args=1.., value_delimiter=',')]
    string: Option<Vec<String>>,

    /// Filter Packets by Time
    /// 
    /// Pass two time values separated by an underscore `_`. Like '-t 12:48_13:25' or '-t _15:37'.
    /// A Time has to be formatted in one of the following Ways: '13', '13:07' or '13:07:21'.
    /// Not providing a value on one side filters from/to the beginning/end of the file to/from the given time.
    #[arg(short, long, value_delimiter='_', verbatim_doc_comment)]
    time: Option<Vec<String>>,

    /// Match only Request Packets
    #[arg(long)]
    request: bool,

    /// Match only Response Packets
    #[arg(long)]
    response: bool,


    /// Prints the Packets Info line and Basic SIP Headers only 
    #[arg(short = 'R', long = "reduced")]
    print_reduced: bool,

    /// Prints the Packets "Raw" like they where provided in the input
    #[arg(long = "raw")]
    print_raw: bool,

    /// Prints the Packets without SDP
    #[arg(long = "no-sdp")]
    no_sdp: bool,
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
        x if x >= 600 => format!("{} {}", response_code.magenta(), spaced_response_text.bright_white().on_magenta()),
        x if x >= 500 => format!("{} {}", response_code.red(), spaced_response_text.bright_white().on_red()),
        x if x >= 400 => format!("{} {}", response_code.red(), spaced_response_text.bright_white().on_red()),
        x if x >= 300 => format!("{} {}", response_code.yellow(), spaced_response_text.bright_white().on_yellow()),
        x if x >= 200 => format!("{} {}", response_code.green(), spaced_response_text.bright_white().on_bright_green()),
        _ => format!("{} {}", response_code, spaced_response_text.bright_white().on_black())
    }



}




fn color_request_method(method: &String) -> ColoredString {

    let spaced_method: String = format!(" {} ", method);

    match method.as_str() {
        "REGISTER" => spaced_method.bright_white().on_magenta(),
        "INVITE" => spaced_method.bright_white().on_blue(),
        "UPDATE" => spaced_method.bright_white().on_cyan(),
        "CANCEL" => spaced_method.bright_white().on_red(),
        "BYE" => spaced_method.bright_white().on_yellow(),
        _ => spaced_method.bright_white().on_black()
    }

}




fn parse_to_net(ipv4: &String) -> Ipv4Net {

    return match ipv4.parse() {
        Ok(ip) => ip,
        Err(_e) => {

            let inputip: Ipv4Addr = match ipv4.parse() {
                Ok(ip) => ip,
                Err(_e) => {
                    eprintln!("[Error] Unable to parse given IP '{}'", ipv4);
                    std::process::exit(1);
                }
            };

            Ipv4Net::new(inputip, 32).unwrap() // Could this be unsafe, theoretically not?

        }

    };
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

    // Don't print filtered Packages
    if !packet_obj.filter_out {

        // ### Print RAW
        if args.print_raw {
            
            if args.print_reduced {
                println!("{}", packet_buffer[0]);

            }else{
                for pbl in packet_buffer {
                    if args.no_sdp {
                        if &pbl[1..2] != "=" {
                            println!("{}", pbl)
                        }
                    }else{
                        println!("{}", pbl)
                    }
                }
                print!("\n");
            }

        
        }else{

            // ### Print Fancy

            // Print Packet info
            let mut _pinfo: String = String::new();
            if packet_obj.outgoing {
                _pinfo = format!("({}) {}:{} -->> {}:{} ({} bytes)", packet_obj.time.format("%Y-%m-%d %H:%M:%S").to_string().bright_blue(), packet_obj.srcip.to_string().bright_green(), packet_obj.srcport.to_string().green().dimmed(), packet_obj.dstip.to_string().bright_red(), packet_obj.dstport.to_string().red().dimmed(), packet_obj.payload_size);
            }else{
                _pinfo = format!("({}) {}:{} <<-- {}:{} ({} bytes)", packet_obj.time.format("%Y-%m-%d %H:%M:%S").to_string().bright_blue(), packet_obj.dstip.to_string().bright_green(), packet_obj.dstport.to_string().green().dimmed(), packet_obj.srcip.to_string().bright_red(), packet_obj.srcport.to_string().red().dimmed(), packet_obj.payload_size);
            }
            println!("{}", _pinfo);


            
            if !packet_obj.error {

                if !args.print_reduced {

                    // Print Status Line
                    let mut _pstatus: String = String::new();
                    if packet_obj.isresponse {
                        _pstatus = format!("{} {}", packet_obj.sip_version, color_response_method(&packet_obj.response_code, &packet_obj.response_text)); 
                    }else {
                        _pstatus = format!("{} {} {}", color_request_method(&packet_obj.sip_method), packet_obj.request_uri, packet_obj.sip_version);
                    }
                    println!("{}", _pstatus);
                    
                    // Print SIP
                    if packet_obj.sip.len() > 0 {
                        for (key, value) in &packet_obj.sip {
                            
                            // ### CALL-ID ###
                            if key == "Call-ID" {
                                let atidx = value.find("@").unwrap_or(value.len());
                                println!("{}: {}{}", key.bright_white(), value[..atidx].to_string().purple(), value[atidx..].to_string());
                            
                            // ### FROM / TO ###
                            }else if key == "From" || key == "To" || key == "P-Asserted-Identity" {
                                // Try to narrow down the string to the actual number, not the whole URI
                                let startidx = value.find(":").and_then(|x| Some(x+1)).unwrap_or(0);
                                let mut endidx = value.find("@").unwrap_or( value.find(">").unwrap_or(value.len()));
                                if endidx > value.find(";").unwrap_or(value.len()) {
                                    endidx = value.find(";").unwrap_or(value.len())
                                }
                                println!("{}: {}{}{}", key.bright_white(), value[..startidx].to_string(), value[startidx..endidx].to_string().yellow(), value[endidx..].to_string());
                                
                            // ### CSEQ ###
                            }else if key == "CSeq" {
                                let slice = value.split_at(value.find(" ").and_then(|x| Some(x+1)).unwrap_or(0));
                                println!("{}: {}{}", key.bright_white(), slice.0, slice.1.to_string().blue());
                                
                            // ### Contact ###
                            }else if key == "Contact" {
                                let startidx = value.find("@").and_then(|x| Some(x+1)).unwrap_or(value.find(":").and_then(|x| Some(x+1)).unwrap_or(0));

                                let semicolon = value.find(";").unwrap_or(value.len());
                                let tribracket = value.find(">").unwrap_or(value.len());

                                if semicolon == tribracket {
                                    println!("{}: {}", key.bright_white(), value);
                                }else if semicolon < tribracket{
                                    println!("{}: {}{}{}", key.bright_white(), value[..startidx].to_string(), value[startidx..semicolon].to_string().bright_cyan(), value[semicolon..].to_string());
                                }else{
                                    println!("{}: {}{}{}", key.bright_white(), value[..startidx].to_string(), value[startidx..tribracket].to_string().bright_cyan(), value[tribracket..].to_string());
                                }

                            // ### REASON ###
                            }else if key == "Reason" {
                                if packet_obj.response_code.parse().unwrap_or(-1) >= 400 {
                                    println!("{}: {}", key.bright_white(), value.red().to_string());
                                }else {
                                    println!("{}: {}", key.bright_white(), value);
                                }
                            
                            }else{
                                println!("{}: {}", key.bright_white(), value);
                            }

                        }
                        print!("\n");
                    }
                    

                    // Print SDP
                    if packet_obj.sdp.len() > 0 && !args.no_sdp {
                        for value in &packet_obj.sdp {
                            
                            // ### RTP IP ###
                            if value.starts_with("c=") {
                                let ipidx = value.find("IP4 ").and_then(|x| Some(x+4)).unwrap_or(value.find("=").and_then(|x| Some(x+1)).unwrap_or(0));
                                println!("{}{}", value[..ipidx].to_string(), value[ipidx..].to_string().bright_cyan());
                                
                            // ### RTP Codecs ###
                            }else if value.starts_with("a=rtpmap:") {
                                let slidx = value.find("/").unwrap_or(value.len());
                                println!("{}{}{}", value[..9].to_string(), value[9..slidx].to_string().green(), value[slidx..].to_string());
                                
                            }else{
                                println!("{}", value);
                            }
                        }
                        print!("\n");
                    }
                    

                    // Other Lines?
                    if packet_obj.other.len() > 0 {
                        for value in &packet_obj.other {
                            println!("{}", value.dimmed())
                        }
                        println!("[WARNING] This Packet contained the above Lines which do not follow the 'Header: Value' or 'a=sdpvalue' structure");
                        print!("\n");
                    }

                    // println!("---");
                    
                }else {

                    // ### Print Fancy Reduced ###

                    // Print Status Line
                    let mut _pstatus: String = String::new();

                    // From
                    let mut c_from: String = packet_obj.sip.get("From").unwrap_or(&_pstatus).to_string();
                    let startidx = c_from.find(":").and_then(|x| Some(x+1)).unwrap_or(0);
                    let mut endidx = c_from.find("@").unwrap_or( c_from.find(">").unwrap_or(c_from.len()));
                    if endidx > c_from.find(";").unwrap_or(c_from.len()) {
                        endidx = c_from.find(";").unwrap_or(c_from.len())
                    }
                    c_from = c_from[startidx..endidx].to_string();

                    // To
                    let mut c_to: String = packet_obj.sip.get("From").unwrap_or(&_pstatus).to_string();
                    let startidx = c_to.find(":").and_then(|x| Some(x+1)).unwrap_or(0);
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
                    println!("{}", _pstatus);

                    print!("\n");
                }


            }else{
                println!("  [Error] {}\n", packet_obj.error_text)
            }


        }

    }

}




fn filter_packet(args: &Args, packet_obj: &mut Packet, packet_buffer: &Vec<String>) {

    // Check if filters are beeing used and hide every packet by default
    if args.number.is_some() || args.ip.is_some() || args.srcip.is_some() || args.dstip.is_some() || args.port.is_some() || 
        args.srcport.is_some() || args.dstport.is_some() || args.external || args.call_id.is_some() || args.string.is_some() || 
        args.method.is_some() || args.status_code.is_some() || args.cseq_method.is_some() || args.request || args.response || 
        args.from.is_some() || args.to.is_some() || args.time.is_some() {

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
                if args.from.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && from.contains(&arg.to_lowercase()) ) {
                    filter_results.insert("from".to_string(), true);
                }else {
                    filter_results.insert("from".to_string(), false);
                }
            } 
            
            // --to
            if args.to.is_some() {
                if args.to.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && to.contains(&arg.to_lowercase()) ) {
                    filter_results.insert("to".to_string(), true);
                }else {
                    filter_results.insert("to".to_string(), false);
                }
            } 
            
            // --number
            if args.number.is_some() {
                if args.number.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && (from.contains(&arg.to_lowercase()) || to.contains(&arg.to_lowercase())) ) {
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



        // ### EXTERNAL ### 
        if args.external {
            if !packet_obj.srcip.is_private() || !packet_obj.dstip.is_private() {
                filter_results.insert("external".to_string(), true);
            }else {
                filter_results.insert("external".to_string(), false);
            }
        }



        // ### CALL-ID ### 
        if args.call_id.is_some() {

            let empty = "".to_string();
            let cid = packet_obj.sip.get("Call-ID").unwrap_or(&empty);
            let atidx = cid.find("@").unwrap_or(cid.len());

            if args.call_id.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && cid[..atidx].contains(arg)) {
                filter_results.insert("call_id".to_string(), true);
            }else{
                filter_results.insert("call_id".to_string(), false);
            }


        }



        // ### SIP-METHOD / RES-TEXT ### 
        if args.method.is_some() {
            if args.method.as_ref().unwrap().into_iter().any(|arg| !arg.trim().is_empty() && (&packet_obj.sip_method.to_uppercase() == &arg.to_uppercase() || &packet_obj.response_text.to_uppercase()  == &arg.to_uppercase()) ) {
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
                            println!("[Error] {}", errstr_format);
                            std::process::exit(1);
                        }

                        let mut hour: u32 = 0;
                        let mut minute: u32 = 0;
                        let mut second: u32 = 0;

                        // Evaluate every hour, minute an second 
                        for (idx, sp) in split.enumerate() {

                            if sp.len() != 2 {
                                println!("[Error] {}", errstr_format);
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
                                println!("[Error] Unable to parse Time '{}'.{}{}", timevec.join("_"), errstr_nl, errstr_format);
                                std::process::exit(1);
                            }

                        }else if timeidx == 1 {
                            totime = NaiveTime::from_hms_opt(hour, minute, second);
                                
                            if totime.is_none() {
                                println!("[Error] Unable to parse Time '{}'.{}{}", timevec.join("_"), errstr_nl, errstr_format);
                                std::process::exit(1);
                            }
                        }
                    }
                }

            }else{
                println!("[Error] To pass a Time Filter two values are needed, separated by an underscore (_). Like '-t 12:48_13:25' or '-t _15:37'. \n        Not providing a value on one side filters from/to the beginning/end of the file to/from the given time.{}{}", errstr_nl, errstr_format);
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
                println!("[Error] To pass a Time Filter two values are needed, separated by an underscore (_). Like '-t 12:48_13:25' or '-t _15:37'. \n        Not providing a value on one side filters from/to the beginning/end of the file to/from the given time.{}{}", errstr_nl, errstr_format);
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
        



        // ### Evalutes Package treatment based on Filter joining Method ###
            if !args.or_filter {
                // AND
                if !args.not_filter && filter_results.values().into_iter().all(|x| *x) { 
                    packet_obj.filter_out = false; 
                    
                }else if args.not_filter && filter_results.values().into_iter().all(|x| !*x) {
                    packet_obj.filter_out = false;
                }
            }else{
                // OR
                if !args.not_filter && filter_results.values().into_iter().any(|x| *x) {
                    packet_obj.filter_out = false;
                } else if args.not_filter && filter_results.values().into_iter().any(|x| !*x) {
                    packet_obj.filter_out = false;
                }
            }

        // // DEBUG
        // for x in &filter_results {
        //     println!("-> {:?}", x);
        // }
        // print!("\n");
        
    }

}




fn parse_packet(packet_buffer: &mut Vec<String>, packet_obj: &mut Packet) {

    for (idx, line) in packet_buffer.iter().enumerate(){
        
        match idx {
            // PACKET INFO
            0 => {
                
                if line.starts_with("("){
                    
                    // Split the line into sections by spaces 
                    let info: Vec<&str> = line.split(" ").into_iter().collect();
                    
                    // Check if it has enough Elements
                    if info.len() >= 9 {

                        // TIME : Parse current Time and update the Time in the initialized Object if Ok
                        let parsedtime = match NaiveTime::parse_from_str(&info.get(0).unwrap_or(&"(00:00:00.00)")[1..12], "%H:%M:%S%.f") {
                            Ok(time) => NaiveDateTime::new(Local::now().date_naive(), time),
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
                        let host_one: &str = &info.get(3).unwrap_or(&"<0.0.0.0:0>");
                        let host_one_split: &Vec<&str> = &host_one[1..&host_one.len()-1].split(":").collect();
                        
                        let host_two: &str = &info.get(8).unwrap_or(&"<0.0.0.0:0>");
                        let host_two_split: &Vec<&str> = &host_two[1..&host_two.len()-1].split(":").collect();
            
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
                        packet_obj.response_text = statusline.get(2).unwrap_or(&"").trim().to_string();
                        
                    }else if SIP_METHODS.iter().any(|s| statusline.get(0).unwrap_or(&"").trim().to_uppercase().starts_with(*s)) {
                        // Packet is a SIP Request
                        packet_obj.isresponse = false;
                        packet_obj.sip_method = statusline.get(0).unwrap_or(&"").trim().to_string();
                        packet_obj.request_uri = statusline.get(1).unwrap_or(&"").trim().to_string();
                        packet_obj.sip_version = statusline.get(2).unwrap_or(&"").trim().to_string();
                        
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
                            let value = slices.1[1..].trim().to_string();
                            
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




fn handle_log_line(args: &Args, packet_buffer: &mut Vec<String>, mut packet_obj: &mut Packet, line: &String){
    
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
                parse_packet(packet_buffer, &mut packet_obj);
                filter_packet(args, &mut packet_obj, packet_buffer);
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
    let args = Args::parse();

    let mut packet_buffer: Vec<String> = Vec::new();
    let mut packet_obj: Packet = Packet::new(); 

    // Checks if a file path is provided
    match args.input_file {
        None => {
            // ### Method 1: Read stdin if there is Data ###

            // Checks if stdin is empty and terminate in case
            if atty::is(atty::Stream::Stdin){
                // println!("[Error] No input was given. Please provide a file path or use a pipe (The use of `tail -f` is discouraged).\n\n{} xsip [OPTIONS] [INPUT_FILE]", "Usage:".underline());
                println!("Usage: xsip [INPUT_FILE] [OPTIONS] \nTry 'xsip -h' or 'xsip --help' for more information.");
                return;
            }

            // Read and process stdin 
            let mut line = String::new();

            // Read line by line while reusing the same line var -> more efficient
            while io::stdin().lock().read_line(&mut line).is_ok_and(|x| x != 0) {

                line = line.strip_suffix("\r\n")
                            .or(line.strip_suffix("\n"))
                            .unwrap_or(&line).to_string();

                handle_log_line(&args, &mut packet_buffer, &mut packet_obj, &line);

                line.clear();
            }

        },

        Some(ref path) => {
            // Check if file path and stdin are provided an warn the user
            if !atty::is(atty::Stream::Stdin){
                println!("[WARNING] Avoid passing xsip a file path and pipeing something into it! Continuing with the Filepath...");
            }

            // Check if file path exists
            if path.exists() {

                // Checks if it should enable follow mode 
                if !args.follow {
                    // ### Method 2: Read whole file normally ###

                    if path.file_name().unwrap_or(OsStr::new("")).to_string_lossy().contains(".gz") {

                        println!("[Info] Found compressed file, using GzDecoder...\n");

                        // Compressed File
                        if let Ok(file) = fs::File::open(path) {
                            
                            let mut reader = BufReader::new(GzDecoder::new(file));
                            let mut line = String::new();
                            
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

                                handle_log_line(&args, &mut packet_buffer, &mut packet_obj, &line);

                                line.clear();
                            }

                        }else {
                            println!("[Error] Unable to open file '{}'", path.display());
                        }
                        
                    }else{

                        // Uncompressed File
                        if let Ok(file) = fs::File::open(path) {

                            let mut reader: Box<dyn BufRead> = Box::new(BufReader::new(file));
                            let mut line = String::new();

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

                                handle_log_line(&args, &mut packet_buffer, &mut packet_obj, &line);

                                line.clear();
                            }

                        }else {
                            println!("[Error] Unable to open file '{}'", path.display());
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

                                // println!("::w:: Event: {:?}", _event); // DEBUG
                                
                                match _event.kind {
                                    
                                    // If Event says that file was modified and exists read new characters
                                    EventKind::Modify(ModifyKind::Data(DataChange::Any)) => {

                                        if Path::new(&eventlistenerpath).exists() {

                                            let mut f = std::fs::File::open(&eventlistenerpath).expect("[Error] Couldn't read file");
                                            
                                            let lastpos = pos.load(Ordering::SeqCst);
                                            let mut curpos = f.metadata().expect("TODO-TEMP").len();
                                            
                                            
                                            // ignore any event that didn't change the pos (file actually not modified)
                                            if !(curpos == lastpos) {
                                                // println!("::w:: Size drinnen: {:?} -> {:?}", lastpos, f.metadata().unwrap().len()); // DEBUG
        
                                                if curpos < lastpos {
                                                    curpos = 0; 
                                                }
        
                                                // Set cursor to lastpos
                                                f.seek(std::io::SeekFrom::Start(lastpos)).expect("TODO-TEMP");
                                                
                                                // Read from lastpos to current end of file
                                                let mut reader: Box<dyn BufRead> = Box::new(BufReader::new(&f));
                                                let mut line = String::new();

                                                // Update lastpos
                                                pos.store(curpos, Ordering::SeqCst);
                                                
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

                                                    handle_log_line(&args, &mut packet_buffer, &mut packet_obj, &line);

                                                    line.clear();
                                                }
                                            }
                                        }

                                    }

                                    _ => { }
                                }

                            }
                            Err(_error) => {
                                println!("{_error:?}");
                                thread::sleep(time::Duration::from_millis(1000));
                            }
                        }
                    }).expect("TODO-TEMP");



                    
                    // Start watching the given path. Calls previously defined Code on Event Trigger
                    watcher.watch(Path::new(&watcherpath), RecursiveMode::Recursive).expect("TODO-TEMP");


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

                                watcher.watch(Path::new(&watcherpath), RecursiveMode::Recursive).expect("TODO-TEMP");   
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
                                println!("[INFO] File was moved/deleted and not recreated");
                                break; 
                            }
                        }
                    }

                }

            }else{
                println!("[Error] This file doesn't exist: \'{}\'", path.display())
            }
        }
    }


}
