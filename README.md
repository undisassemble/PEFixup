# PEFixup

Just some stuff I thought would be useful when working with packed binaries.

Please note this is not intended to produce working binaries, and will not provide any help with some tasks such as IAT reconstruction.

## Features

- Disable ASLR
- Find & remove invalid TLS callbacks
- Dump running process by name/PID
- Specify base address of process
- Specify headers for process
- Dump specific module from process
- Perform signature based scanning for common entry points and TLS callbacks
- Supports 32 and 64 bit

## Usage

```
Usage: PEFixup.exe COMMAND FILE [OPTIONS]

COMMAND
        pre             Intended for use before running and dumping an application
        dump            Dump a running process to disk
        post            Intended for use on a dumped application

GENERAL OPTIONS
        -o OUTPUT       Select output path
        --help          Display this menu

PRE OPTIONS
        --no-aslr       Don't touch ASLR, leave as is
        --no-tls        Don't remove invalid TLS callbacks

DUMP OPTIONS
        --pid           FILE is the PID of a running process
        --name          FILE is the name of a running process
        --base ADDRESS  Base address of running process/dumped PE
        --headers FILE  Specify PE that contains dumped PE's headers
        --module NAME   Dump a loaded module in the process, instead of the process itself

POST OPTIONS
        --headers FILE  Specify PE that contains dumped PE's headers
        --no-oep        Don't scan for possible OEP
        --no-tls        Don't scan for possible TLS callbacks
        --no-debug      Don't remove debugging information
        --dumped        FILE is a raw dump and needs to be adjusted to disk format
        --x-only        Only scan executable memory
```

Example (dumping a process that cleared its base address and headers): `PEFixup dump process.exe --name --base 140000000 --headers C:\path\to\process.exe -o process_dumped.exe`

I don't recommend using `pre` at all if your binary checks itself for modifications.