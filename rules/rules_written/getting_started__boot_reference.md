# Reference Design Boot Walkthrough

Source: https://rules.ectf.mitre.org/2026/getting_started/boot_reference.html

# Reference Design Boot Walkthrough[¶](#reference-design-boot-walkthrough "Permalink to this heading")

This section will help you with getting your machine running the eCTF
[Reference Design](../system/reference_design.html). We will be discussing each of the steps to take you
through the initialization!

First we will discuss the required components, programs, and anything else
that you need to succeed! Please refer to the [Machine Setup](machine_setup.html) steps to make sure
everything is downloaded.

Depending on the Operating System of you machine, you will need to follow
different steps. This is because the commands are different for
[Linux](#boot-linux) based machines and
[Windows](#boot-windows) based machines.

Warning

**When creating your own design, make sure that your repository is not made public,**
**otherwise, other teams will be able to see your design in-progress before the**
**Attack Phase!!**

## Windows[¶](#windows "Permalink to this heading")

### Cloning the Reference Design[¶](#cloning-the-reference-design "Permalink to this heading")

Next, we need to download the Reference Design. To do so, we will need to create
a new folder. In your file explorer, create a new folder in a location in which
you will not forget where it is located. Click on the newly created folder. Next
at the top of the window, you will see a text box with your file path included
there. You will click on the textbox and highlight everything within that box.
Then you must type “powershell” and hit enter. This will bring up a powershell
window where you can type commands.

When you encounter multiple commands in this Walkthrough, they will be separated
by a new line. If there are multiple commands listed, enter commands
sequentially in order as most commands are dependent on previous commands. You
can copy and paste these commands directly into your PowerShell window!

Note

You will need to have git installed to proceed

To download the reference design repo, run the following command.

```
git clone https://github.com/ectfmitre/2026-ectf-insecure-example/
```

This will clone the insecure design to your local machine.

In your file explorer locate the root of the cloned files. It should contain folders named:
`firmware` and `ectf26_design`. Open a new PowerShell window in this directory.

### Managing the Python Environment[¶](#managing-the-python-environment "Permalink to this heading")

This year we will be using [uv](https://docs.astral.sh/uv/).

```
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Once installed uv manages all the packages like magic!

To run a script use:

```
uv run path/to/script.py
```

And to use a python tool:

```
uvx --from 'package-name' tool arg1 arg2
```

Use uv to install the ectf host tools for the competition:

```
uvx ectf --help
```

Now you can execute the tools needed for the competition by running

```
uvx ectf <tool_name>
```

### Locating the Serial Port[¶](#locating-the-serial-port "Permalink to this heading")

Note

Before you can proceed with this step, ensure that your device is connected
correctly. See [MSP-LITO-L2228 Board](mspm0l2228.html)

The first step to flash the board with the reference design, is to know
where the data should be sent. The board uses serial communication meaning we must
know what port on our computer the device is plugged into. To locate the name of said port
you must open the Device Manager on your computer. There are a handful of ways of
doing so. You can press the Windows key and ‘R’ simultaneously and type ‘devmgmt.msc’
then click OK. Another way is to press the windows key and in the search bar, look up
“Device Manager” and then click ‘Open’.

You will see a long list of devices. The device manager allows us to monitor hardware
that is connected to our computer. Now that you have the device manager open, plug the
board into your computer. The list should refresh and a new item to the list should
have been made labeled ‘Ports (COM & LPT)’. Click the arrow to bring up the drop down
menu. You will see a device listed there which is labeled as “COMxx” where the x’s are
the respective port on your computer in which you plugged the device into. Take note
of this port each time you plug the device into your system as it will change frequently.

Note

You will need to have [Docker](docker.html) installed and working to progress.

### Creating a Deployment[¶](#creating-a-deployment "Permalink to this heading")

We will start by creating the global secrets, which will be used by all HSMs
in this deployment.

```
# Generate secrets, storing them in the file `global.secrets` and
# defining the valid groups as 1, 2, and 3
uv pip install -e .\ectf26_design\
uv run secrets .\global.secrets 1 2 3 0x1111
```

Next, we will create the build environment, which will create a [Docker](docker.html)
image that will be used to build HSMs. Please run:

```
# Build the docker container, tagging it as `build-hsm` and using
# the local directory `./firmware` as the build context
docker build -t build-hsm ./firmware
```

Building this image will take some time, roughly about 10 minutes. If it is
taking an abnormally long time, you can try closing the Docker application and
reopening it, or a full power cycle of your computer should resolve any issues.

Tip

In general, this Docker build step will only need to be run once. However,
if you change dependencies, you will need to re-run this to rebuild the
`build-hsm` image.

### Building an HSM[¶](#building-an-hsm "Permalink to this heading")

With the environment built, you can now build a [Hardware Security Module (HSM)](../system/index.html#hsm). This will
use the `build-hsm` Docker image, mounting local directories with the
HSM source code, the global secrets, and an output directory for built
artifacts.

```
# Build a HSM in a Docker container:
#   `--rm` Delete the container when finished (remove when debugging to see output after completion)
#   `-v .\firmware/:/hsm` Mount the local directory `firmware/` to `/hsm` in the container
#   `-v .\global.secrets:/secrets/global.secrets` Mount the file `global.secrets` to `/secrets/global.secrets` in the container
#   `-v .\build:/out` Mount the local directory `build/` to `/out` in the container
#   `-e HSM_PIN=abc123` Define the secret pin of the HSM (with up to 6 hex digits)
#   `-e PERMISSIONS='1234=R--:4321=RWC' Define the file permissions this hsm has
#   `build-hsm` Specify the tag of the Docker image to use
docker run --rm -v .\firmware:/hsm -v .\global.secrets:/secrets/global.secrets:ro -v .\build:/out -e HSM_PIN='abc123' -e PERMISSIONS='1234=R--:4321=RWC' build-hsm
```

### Flashing the HSM Firmware[¶](#flashing-the-hsm-firmware "Permalink to this heading")

Note

Before proceeding with this section, ensure you have installed the
[eCTF Bootloader](../system/bootloader.html)

The first step to flash the design is to place the device in update mode. Hold down the
PB21 button on at the bottom of the board and tap the NRST button. If the LED PB14 is
blinking red, then your device is in update mode.

Now that we are in update mode, we can now flash the board. Enter the
following command to flash the board:

Tip

Remember the port we identified earlier? Replace the section labeled `COM3`
with the port you located.

```
# Erase the flash contents just to be sure
uvx ectf hw COM3 erase
# Flash an HSM
#    `.\build\hsm.bin` Path to the built HSM
#    `COM3` COM port to use to connect to the board
uvx ectf hw COM3 flash .\build\hsm.bin -n hsm
# This command will start the application you just flashed
uvx ectf hw COM3 start
```

Now if the LED has changed to solid RED, then the reference design is running. The final
step to getting the Boot the Reference flag, is to run a list command.

```
uvx ectf tools COM3 list
```

### Example Use Case[¶](#example-use-case "Permalink to this heading")

Now that you’ve successfully booted one HSM, we will go over a slightly more complicated
example an example of how to use two HSMs under a standard operation. We’ll first need
to provision two HSMs

```
# build the binary for HSM A
docker run --rm -v .\firmware:/hsm -v .\global.secrets:/secrets/global.secrets:ro -v .\build:/out -e HSM_PIN='abc123' -e PERMISSIONS='1111=-W-' build-hsm
# built the binary for HSM B
docker run --rm -v .\firmware:/hsm -v .\global.secrets:/secrets/global.secrets:ro -v .\build:/out -e HSM_PIN='567def' -e PERMISSIONS='1111=R-C' build-hsm
```

First, on HSM A write the contents of file an example file called example.txt.

```
echo asdf > example.txt
uvx ectf tools COM12 write 123abc 0 0x1111 .\example.txt
# Then we should be able to see this file when we list
uvx ectf tools COM12 list 123abc
```

```
Got DEBUG message: b'Boot Reference Flag: ectf{REDACTED}\n'
Got DEBUG message: b'Checking PIN\n'
Found file: Slot 0, Group 1111, example.txt
List successful
```

Now connect the two HSMs over UART1 then set HSM A to listen for interrogate and receive commands

```
uvx ectf tools COM12 listen
```

Then on HSM B run

```
uvx ectf tools COM13 interrogate 567def
```

This will return the file slots of files that this HSM has permissions to receive which
can be done with (after putting A in listen mode again):

```
uvx ectf tools COM13 receive 567def 0 0
```

The file should now be stored on HSM B which can be read out in plain text with:

```
mkdir output
uvx ectf tools COM13 read -f 567def 0 .\output\
```

## Linux[¶](#linux "Permalink to this heading")

### Cloning the Reference Design[¶](#id1 "Permalink to this heading")

We first need to download the Reference Design. To do so, we will need to create a new
folder. In your file explorer, create a new folder in a location in which you will not
forget where it is located. Click on the newly created folder. This folder will be known as the
root folder. While within this folder, right click on the window, and select the option labeled “Terminal”.
This will open a new terminal window with the file path of the root folder.

When you encounter multiple commands in this Walkthrough, they will be separated by a new line.
If there are multiple commands listed, enter commands sequentially in order as most commands are
dependent on previous commands. You can copy and paste these commands directly into your Terminal window!

Note

You will need to have git installed to proceed

To download the reference repo, run the following command.

```
git clone https://github.com/ectfmitre/2026-ectf-insecure-example/
```

This will clone the repo so that we have access to the correct files.

### Managing the Python Environment[¶](#id2 "Permalink to this heading")

This year we will be using [uv](https://docs.astral.sh/uv/).

```
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Once installed uv manages all the packages like magic!

To run a script use:

```
uv run path/to/script.py
```

And to use a python tool:

```
uvx --from 'package-name' tool arg1 arg2
```

Use uv to install the ectf host tools for the competition:

```
uvx ectf --help
```

Now you can execute the tools needed for the competition by running

```
uvx ectf <tool_name>
```

### Locating the Serial Port[¶](#id4 "Permalink to this heading")

Note

Before you can proceed with this step, ensure that your device is connected
correctly. See [MSP-LITO-L2228 Board](mspm0l2228.html)

Before we can flash the firmware, we first need to locate which serial port the HSM is
connected to. Locating the port is as simple as copying and pasting commands and
locating differences. We are going to keep the board unplugged, then run the following
command in any terminal to see the list of ports:

```
ls /dev/tty*
```

You will see all of the listed devices. Now plug the eCTF device into the computer and
run the exact same command. You will compare the initial output you got from the first
execution to the second output of the command execution and find the different listed
device. As the eCTF device was the only change we made to the devices plugged in, the
different device will be the port in which the eCTF is connected to. For example, the
identified file may look like:

```
/dev/ttyACM0
/dev/ttyUSB0
/dev/tty.usbmodem11302
```

* Take note of the name of the port as we will need it later

Note

You will need to have [Docker](docker.html) installed and working to progress.

### Creating a Deployment[¶](#id5 "Permalink to this heading")

We will start by creating the global secrets, which will be used by all HSMs
in this deployment.

```
# Generate secrets, storing them in the file `global.secrets` and
# defining the valid groups as 1 and 0x1111
uv pip install -e ./ectf26_design/
uv run secrets ./global.secrets 1 0x1111
```

Next, we will create the build environment, which will create a [Docker](docker.html)
image that will be used to build HSMs. Please run:

```
# Build the docker container, tagging it as `build-hsm` and using
# the local directory `./firmware` as the build context
docker build -t build-hsm ./firmware
```

Building this image will take some time, roughly about 10 minutes. If it is
taking an abnormally long time, you can try closing the Docker application and
reopening it, or a full power cycle of your computer should resolve any issues.

Tip

In general, this Docker build step will only need to be run once. However,
if you change dependencies, you will need to re-run this to rebuild the
`build-hsm` image.

### Building an HSM[¶](#id6 "Permalink to this heading")

With the environment built, you can now build a [Hardware Security Module (HSM)](../system/index.html#hsm). This will
use the `build-hsm` Docker image, mounting local directories with the
HSM source code, the global secrets, and an output directory for built
artifacts.

```
# Build a HSM in a Docker container:
#   `--rm` Delete the container when finished (remove when debugging to see output after completion)
#   `-v ./firmware/:/hsm` Mount the local directory `firmware/` to `/hsm` in the container
#   `-v ./global.secrets:/secrets/global.secrets` Mount the file `global.secrets` to `/secrets/global.secrets` in the container
#   `-v ./build:/out` Mount the local directory `build/` to `/out` in the container
#   `-e HSM_PIN=123abc` Define the secret pin of the HSM (with up to 6 hex digits)
#   `-e PERMISSIONS='1234=R--:4321=RWC' Define the file permissions this hsm has
#   `build-hsm` Specify the tag of the Docker image to use
docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1234=R--:4321=RWC' build-hsm
```

### Flashing the HSM Firmware[¶](#id7 "Permalink to this heading")

Note

Before proceeding with this section, ensure you have installed the
[eCTF Bootloader](../system/bootloader.html)

The first step to flash the design is to place the device in update mode. Hold down the
PB21 button on at the bottom of the board and tap the NRST button. If the LED PB14 is
blinking red, then your device is in update mode.

Now that we are in update mode, we can now
flash the board. Enter the following command to flash the board:

Tip

Remember the port we identified earlier? Replace the section labeled
`usbmodem11302` with the port you located.

```
# Erase the flash contents just to be sure
uvx ectf hw /dev/tty.usbmodem11302 erase
# Flash an HSM
#    `./build/hsm.bin` Path to the built HSM
#    `tty.usbmodem11302` port to use to connect to the board
uvx ectf hw /dev/tty.usbmodem11302 flash ./build/hsm.bin -n hsm
# This command will start the application you just flashed
uvx ectf hw /dev/tty.usbmodem11302 start
```

Now if the LED has changed to solid RED, then the reference design is running. The final
step to getting the Boot the Reference flag, is to run a list command.

```
uvx ectf tools /dev/tty.usbmodem11302 list
```

### Example Use Case[¶](#id8 "Permalink to this heading")

Now that you’ve successfully booted one HSM, we will go over a slightly more complicated
example an example of how to use two HSMs under a standard operation. We’ll first need
to provision two HSMs

```
# build the binary for HSM A
docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1111=-W-' build-hsm
# built the binary for HSM B
docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='567def' -e PERMISSIONS='1111=R-C' build-hsm
```

Firstly on HSM A write the contents of file an example file called example.txt.

```
echo asdf > example.txt
uvx ectf tools /dev/tty.usbmodem11302 write 123abc 0 0x1111 ./example.txt
# Then we should be able to see this file when we list
uvx ectf tools /dev/tty.usbmodem11302 list 123abc
```

```
Got DEBUG message: b'Boot Reference Flag: ectf{REDACTED}\n'
Got DEBUG message: b'Checking PIN\n'
Found file: Slot 0, Group 1111, example.txt
List successful
```

Now connect the two HSMs over UART1 then set HSM A to listen for interrogate and receive commands

```
uvx ectf tools /dev/tty.usbmodem11302 listen
```

Then on HSM B run

```
uvx ectf tools /dev/tty.usbmodem11303 interrogate 567def
```

This will return the file slots of files that this HSM has permissions to receive which
can be done with (after putting A in listen mode again):

```
uvx ectf tools /dev/tty.usbmodem11303 receive 567def 0 0
```

The file should now be stored on HSM B which can be read out in plain text with:

```
mkdir output
uvx ectf tools /dev/tty.usbmodem11303 read -f 567def 0 ./output/
```

