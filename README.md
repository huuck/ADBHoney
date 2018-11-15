#### follow me on twitter @hookgab for the latest updates

# ADBHoney
Low interaction honeypot designed for Android Debug Bridge over TCP/IP

## What's this?
The Android Debug Bridge (ADB) is a protocol designed to keep track of both emulated and real phones/TVs/DVRs connected to a given host. It implements various commands designed to assist the developer (`adb shell`, `adb push`, and so on) in both debugging and pushing content to the device. This is usually done via an attached USB cable, with ample mechanisms of authentication and protection. Turns out though that by a simple adb command (`adb tcpip <port>`) sent to an already established connection (through USB for example), you can force your device to expose its ADB services over port 5555, after which you can use a simple `adb connect <ip>:<port>` to connect to your device via TCP. However, unlike the USB protocol, the TCP one does not have any kind of authentication and leaves the device prone to all kinds of attacks. Two of them are as follows:

`adb shell <shell command>` - allows a developer to run all kinds of commands on the connected device such as ls, wget and many others.

`adb push <local file> <remote destination>` - allows a developer to upload binaries from his own machine to the connected Android device.
Coupled together, these two API calls can allow complete control over the device (legitimate or not) as long as the port is exposed over the Internet.
  
The purpose of this project is to provide a low interaction honeypot designed to catch whatever malware is being pushed by attackers to unsuspecting victims which have port 5555 exposed.

## What works?
Right now you can `adb connect`, `adb push` and `adb shell` into it. All of the data is redirected to stdout and files will be saved to disk. CPU/memory usage should be fairly low, any anormalities should be reported so I can look into them. There's a lot of black magic inside, so please be kind when logging an issue.

## What doesn't work?
More advanced commands (like native directory listing and having and interactive shell) won't work. The main reason is that I haven't found any kind of malware to take advantage of mechanisms like this. I've also had to reverse engineer the protocol flow by hand, so please also provide a **.pcap** when logging an issue so I can look into it (or VERY exact steps for reproduction). Any improvements will be more than welcome.

# OK OK, how do I get it started?
Just start the script in python:

`nohup python main.py &`

Just like that, shouldn't have any more complex dependencies.

I'm working on this in my free time, so it's still a debugging build. You can remove the debug messages by hand or just do a `strings nohup.out | grep -v "<<<<" | grep -v ">>>>" | less` if you want to get some data right away.

## Credits
Hat tip to [sporsh](https://github.com/sporsh) for his [awesome work](https://github.com/sporsh/twisted-adb/blob/master/adb/protocol.py) on providing the community with some wrappers for ADB messages.
