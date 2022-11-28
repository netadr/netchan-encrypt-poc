# PLEASE READ
This is a *proof-of-concept* I wrote in July 2022 for adding an encryption layer to iw4's netchan system.  
It includes a key exchange using Curve25519, and encryption/authentication implemented using XChaCha20-Poly1305.  

Relevant source files are:

[NetchanEncrypt.cpp](src/Components/Modules/NetchanEncrypt.cpp)
[NetchanEncrypt.hpp](src/Components/Modules/NetchanEncrypt.hpp)

![license](https://img.shields.io/github/license/IW4x/iw4x-client.svg)
![forks](https://img.shields.io/github/forks/IW4x/iw4x-client.svg)
![stars](https://img.shields.io/github/stars/IW4x/iw4x-client.svg)
![issues](https://img.shields.io/github/issues/IW4x/iw4x-client.svg)
[![build](https://github.com/XLabsProject/iw4x-client/workflows/Build/badge.svg)](https://github.com/XLabsProject/iw4x-client/actions)
[![discord](https://img.shields.io/endpoint?url=https://momo5502.com/iw4x/members-badge.php)](https://discord.gg/sKeVmR3)
[![patreon](https://img.shields.io/badge/patreon-support-blue.svg?logo=patreon)](https://www.patreon.com/xlabsproject)

# IW4x: Client

## How to compile

- Run `premake5 vs2022` or use the delivered `generate.bat`.
- Build via solution file in `build\iw4x.sln`.

## Premake arguments

| Argument                    | Description                                    |
|:----------------------------|:-----------------------------------------------|
| `--copy-to=PATH`            | Optional, copy the DLL to a custom folder after build, define the path here if wanted. |
| `--copy-pdb`                | Copy debug information for binaries as well to the path given via --copy-to. |
| `--force-unit-tests`        | Always compile unit tests.                     |
| `--force-exception-handler` | Install custom unhandled exception handler even for Debug builds. |
| `--disable-binary-check`    | Do not perform integrity checks on the exe. |
| `--iw4x-zones`              | Zonebuilder generates iw4x zones that cannot be loaded without IW4x specific patches. |

## Command line arguments

| Argument                | Description                                    |
|:------------------------|:-----------------------------------------------|
| `-tests`                | Perform unit tests.                            |
| `-entries`              | Print to the console a list of every asset as they are loaded from zonefiles. |
| `-stdout`               | Redirect all logging output to the terminal iw4x is started from, or if there is none, creates a new terminal window to write log information in. |
| `-console`              | Allow the game to display its own separate interactive console window. |
| `-dedicated`            | Starts the game as a headless dedicated server. |
| `-scriptablehttp`       | Enable HTTP related gsc functions.             |
| `-bigminidumps`         | Include all code sections from loaded modules in the dump. |
| `-reallybigminidumps`   | Include data sections from all loaded modules in the dump. |
| `-dump`                 | Write info of loaded assets to the raw folder as they are being loaded. |
| `-monitor`              | This flag is for internal use and it is used to indicate if an external console is present. |
| `-nointro`              | Skip game's cinematic intro.                   |
| `-version`              | Print IW4x build info on startup.              |
| `-zonebuilder`          | Start the interactive zonebuilder tool console instead of starting the game. |
| `-nosteam`              | Disable friends feature and do not update Steam about the game's current status just like an invisible mode. |


## Disclaimer

This software has been created purely for the purposes of
academic research. It is not intended to be used to attack
other systems. Project maintainers are not responsible or
liable for misuse of the software. Use responsibly.
