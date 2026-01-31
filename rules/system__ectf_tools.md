# eCTF Tools

Source: https://rules.ectf.mitre.org/2026/system/ectf_tools.html

# eCTF Tools[¶](#ectf-tools "Permalink to this heading")

The eCTF Tools allow teams to have a standard interface to the [HSM](index.html#hsm)
functionality described in [Functional Requirements](../specs/functional_reqs.html), the [eCTF bootloader](bootloader.html), and the [eCTF API](api.html).

## Using the eCTF Tools[¶](#using-the-ectf-tools "Permalink to this heading")

This year, the eCTF tools are [published to PyPi](https://pypi.org/project/ectf/). The
supported way to use this toolset is with the `uv` package manager. First, install
`uv` following [their docs](https://docs.astral.sh/uv/getting-started/installation/). Then, all you need to do to
get the `ectf` tools up and running is run `uvx ectf --help` and it will
automatically be installed.

There are a couple of nested command processors:

* `ectf tools` has subcomands that are used to interact with a running [HSM](index.html#hsm). See [HSM Tool Reference Calls](#hsm-tool-calls)
* `ectf api` has subcomands that are used to interact with the [eCTF API](api.html)
* `ectf hw` has subcommands that are used to interact with the [eCTF Bootloader](bootloader.html). See [eCTF Bootloader Tools](#bl-tool-calls)

```
$ uvx ectf --help

Usage: ectf [OPTIONS] COMMAND [ARGS]...

Interact with the eCTF hardware, design, and API

╭─ Options ─────────────────────────────────────────────────────────────────────────────────────╮
│ --verbose             -v      INTEGER  Enable debug prints [default: 0]                       │
│ --install-completion                   Install completion for the current shell.              │
│ --show-completion                      Show completion for the current shell, to copy it or   │
│                                        customize the installation.                            │
│ --help                                 Show this message and exit.                            │
╰───────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────────╮
│ config   Create or update the configuration file                                              │
│ docs     Open the API documentation website                                                   │
│ rules    Open the eCTF rules website                                                          │
│ tools    Run the host tools                                                                   │
│ api      Interact with the API                                                                │
│ hw       Interact with the MITRE bootloader                                                   │
╰───────────────────────────────────────────────────────────────────────────────────────────────╯
```

Warning

uvx will use the currently installed version of ectf by default. If you need to update to
a more recent version, run uvx ectf@latest

## HSM Tool Reference Calls[¶](#hsm-tool-reference-calls "Permalink to this heading")

All host tools are provided by the organizers and create simplistic interfaces
for communication between the [Host Computer](index.html#host-computer) and the
[Hardware Security Module (HSM)](index.html#hsm). These tools define the uniform interface utilized
to meet the technical requirements on the HSM. See [Host Interface](../specs/host_interface.html#host-interface) for the
details of the protocol of the interface the Host Tools use to communicate with
the HSM. These commands are in the `tools` subprocessor.

```
$ uvx ectf tools --help

 Usage: ectf tools [OPTIONS] PORT COMMAND [ARGS]...

 Run the host tools

╭─ Arguments ─────────────────────────────────────────────────────────────╮
│ *    port      TEXT  Serial port [required]                             │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                             │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────╮
│ read          Read a file stored on the HSM                             │
│ write         Write a file stored to the HSM                            │
│ receive       Receive a file stored on another HSM                      │
│ listen        Alert the HSM to listen for another HSM                   │
│ list          List the files stored on the current HSM                  │
│ interrogate   Interrogate files stored on a connected HSM               │
╰─────────────────────────────────────────────────────────────────────────╯
```

### List Tool[¶](#list-tool "Permalink to this heading")

The list tool executes the list command and displays the result from the HSM. The list
tool requires a pin.

```
uvx ectf tools COM10 list --help

 Usage: ectf tools PORT list [OPTIONS] PIN

 List the files stored on the current HSM

╭─ Arguments ─────────────────────────────────────────────────────────────╮
│ *    pin      TEXT  The 6 digit pin to authenticate the HSM device      │
│                     [required]                                          │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                             │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx ectf tools COM10 list 123456
```

### Read File Tool[¶](#read-file-tool "Permalink to this heading")

The read file tool executes the read command and writes the result from the HSM to a
file on the host. The read file tool takes in the pin for the HSM, the slot from which
to read, and the path on the host system to which to write the output file. The read
file tool will send the read command to the HSM and write the file to the directory
specified (it will use the name and contents from the HSM to write it). The force option
must be specified in order to *overwrite* an existing file.

```
uvx ectf tools COM10 read --help

 Usage: ectf tools PORT read [OPTIONS] PIN SLOT READ_FILE_PATH

 Read a file stored on the HSM

╭─ Arguments ─────────────────────────────────────────────────────────────╮
│ *    pin                 TEXT           The 6 digit pin to authenticate │
│                                         the HSM device                  │
│                                         [required]                      │
│ *    slot                INTEGER RANGE  The slot on the device for the  │
│                                         file                            │
│                                         [required]                      │
│ *    read_file_path      PATH           Path to write the file to       │
│                                         [required]                      │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────╮
│ --force  -f                                                             │
│ --help             Show this message and exit.                          │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx uv run ectf tools COM10 read 123456 0 ./out/
```

### Write File Tool[¶](#write-file-tool "Permalink to this heading")

The write file tool executes the write command and returns the result from the HSM. The
write file tool takes in the pin for the HSM, the slot to which to write, the group id
for the file, and a path to the file to write to the system (the host tool will use the
name of that file as well as its contents to determine what is to be written).

```
uvx ectf tools COM10 write --help

 Usage: ectf tools PORT write [OPTIONS] PIN SLOT GID FILE

 Write a file stored to the HSM

╭─ Arguments ─────────────────────────────────────────────────────────────╮
│ *    pin       TEXT            The 6 digit pin to authenticate the HSM  │
│                                device                                   │
│                                [required]                               │
│ *    slot      INTEGER RANGE   The slot on the device for the file      │
│                                [required]                               │
│ *    gid       DEC_OR_HEX_INT  ID of the group that owns the HSM file   │
│                                [required]                               │
│ *    file      FILENAME        Path to a file on the host filesystem to │
│                                send to the HSM                          │
│                                [required]                               │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────╮
│ --uuid  -u      TEXT  UUID of the file [default: (dynamic)]             │
│ --help                Show this message and exit.                       │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx ectf tools COM10 write 123456 1 0x1234 ./asdf.txt
```

### Listen Tool[¶](#listen-tool "Permalink to this heading")

The listen tool executes the listen command and returns the result from the HSM. This
will put the HSM in a state where it can receive cross-HSM communication from the
interrogate files and receive file functionalities.

```
uvx ectf tools COM10 listen --help

 Usage: ectf tools PORT listen [OPTIONS]

 Alert the HSM to listen for another HSM

╭─ Options ───────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                             │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx ectf COM10 listen
```

### Interrogate Files Tool[¶](#interrogate-files-tool "Permalink to this heading")

The interrogate files tool executes the interrogate command and returns a list of files
from the neighboring HSM. The interrogate files tool takes in the pin for the HSM and
outputs the in the same format as the list tool.

```
uvx ectf tools COM10 interrogate --help

 Usage: ectf tools PORT interrogate [OPTIONS] PIN

 Interrogate files stored on a connected HSM

╭─ Arguments ─────────────────────────────────────────────────────────────╮
│ *    pin      TEXT  The 6 digit pin to authenticate the HSM device      │
│                     [required]                                          │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                             │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx ectf tools COM10 interrogate 12345
```

### Receive File Tool[¶](#receive-file-tool "Permalink to this heading")

The receive file tool executes the receive command and returns the result from the HSM.
The receive file tool takes in the pin for the HSM, the slot on the neighbor HSM from
which to read, and the slot on the local HSM to which to write. This copies a file from
a neighbor HSM to the local HSM from which it can then be listed and read with the list
tool and the read file tool.

```
uvx ectf tools COM10 receive --help

 Usage: ectf tools PORT receive [OPTIONS] PIN READ_SLOT WRITE_SLOT

 Receive a file stored on another HSM

╭─ Arguments ─────────────────────────────────────────────────────────────╮
│ *    pin             TEXT           The 6 digit pin to authenticate the │
│                                     HSM device                          │
│                                     [required]                          │
│ *    read_slot       INTEGER RANGE  The slot on the device for the file │
│                                     [required]                          │
│ *    write_slot      INTEGER RANGE  The slot on the device for the file │
│                                     [required]                          │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                             │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx ectf tools COM10 receive 123456 0 0
```

## eCTF Bootloader Tools[¶](#ectf-bootloader-tools "Permalink to this heading")

The `ectf hw` commands are used to interact with the [eCTF bootloader](bootloader.html).

```
uvx ectf hw --help

 Usage: ectf hw [OPTIONS] PORT COMMAND [ARGS]...

 Interact with the MITRE bootloader

╭─ Arguments ─────────────────────────────────────────────────────────────╮
│ *    port      TEXT  Serial port [required]                             │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                             │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────╮
│ status        Get the bootloader status from the MSPM0L2228             │
│ erase         Erase a design from the MSPM0L2228                        │
│ flash         Flash a design onto the MSPM0L2228                        │
│ start         Start the application                                     │
│ reflash       Shortcut for erase, flash, then start                     │
│ digest        Print the cryptographic digest of a file                  │
│ flash_fthr    Flash a design onto the MAX78000FTHR                      │
│ unlock_fthr   Unlock the secure MITRE bootloader of the MAX78000FTHR    │
╰─────────────────────────────────────────────────────────────────────────╯
```

### BL Status Tool[¶](#bl-status-tool "Permalink to this heading")

This tool retrieves the version, whether it is secure or insecure, and the name of the
installed application from the bootloader. It takes no arguments.

```
uvx ectf hw COM10 status --help

 Usage: ectf hw PORT status [OPTIONS]

 Get the bootloader status from the MSPM0L2228

╭─ Options ───────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                             │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx ectf hw COM10 status
```

### BL Erase Tool[¶](#bl-erase-tool "Permalink to this heading")

This tool wipes the APP region of flash. You must run it before installing a new
application. It takes no arguments.

```
uvx ectf hw COM10 erase --help

 Usage: ectf hw PORT erase [OPTIONS]

 Erase a design from the MSPM0L2228

╭─ Options ───────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                             │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx ectf hw COM10 erase
```

### BL Flash Tool[¶](#bl-flash-tool "Permalink to this heading")

This tool is used to flash an application onto the MSPM0L2228. The bootloader must be
erased prior to flashing. This command takes a path to the application image as an
argument.

```
uvx ectf hw COM10 flash --help

 Usage: ectf hw PORT flash [OPTIONS] INFILE

 Flash a design onto the MSPM0L2228

╭─ Arguments ─────────────────────────────────────────────────────────────╮
│ *    infile      PATH  Path to the build output (e.g., abc.hsm)         │
│                        [required]                                       │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────╮
│ --name  -n      TEXT  Name of the binary                                │
│ --help                Show this message and exit.                       │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx ectf hw COM10 flash ./2026-ectf-insecure-example/build.hsm/ -n HSM
```

### BL Start Tool[¶](#bl-start-tool "Permalink to this heading")

This tool exits bootloader mode and boots the user application. It does not require any
arguments.

```
uvx ectf hw COM10 start --help

 Usage: ectf hw PORT start [OPTIONS]

 Start the application

╭─ Options ───────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                             │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx ectf hw COM10 start
```

### BL Digest Tool[¶](#bl-digest-tool "Permalink to this heading")

This tool queries the bootloader for a file digest. It takes a slot as an argument.

```
uvx ectf hw COM10 digest --help

 Usage: ectf hw PORT digest [OPTIONS] SLOT

 Print the cryptographic digest of a file

╭─ Arguments ─────────────────────────────────────────────────────────────╮
│ *    slot      INTEGER  Slot of the file [required]                     │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                             │
╰─────────────────────────────────────────────────────────────────────────╯
```

Example Utilization:

```
uvx ectf hw COM10 digest 0
```

