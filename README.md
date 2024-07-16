# xsip
A command-line tool to extract and filter SIP messages from Cirpack pcscf and ibcf log files.

---

### Build
To make this work on RHEL you probably need to use the "musl" C-Library instead of the defualt "glibc".
<br>

##### Using system default (probably glibc)
```cargo build --release```
<br>


##### Using musl
1. Install the MUSL component with rustup: <br>```rustup component add rust-std-x86_64-unknown-linux-musl```<br>
2. Build using it: <br>```cargo build --release --target x86_64-unknown-linux-musl``` <br>


### Deploy
To deploy the program, simply upload the binary to a directory listed in PATH.