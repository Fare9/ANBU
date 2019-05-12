# ANBU
*Automatic New Binary Unpacker with PIN DBI Framework*
This project is considered more an academic project than something professional or company software, I have it as a way for me to learn about how to use PIN and how to implement interesting things with it, so pull request are welcome.

## First of All: Compiling ANBU

To compile ANBU you need to download PIN, and you can download it from here: [Intel PIN][1]. Once you have PIN on your system, you have to copy ANBU folder on <pin_path>/source/tools/ path, also you can create another folder instead of "tools" I created one called "unpackers". Once you have the path <pin_path>/source/tools or unpackers/ANBU, you can open ANBU.sln file with Visual Studio, in my case I use Visual Studio 2017. To compile I do nothing special more than compile the project I compile on "Release" for "x86" (I haven't tested or programmed ANBU for x64 for the moment). And that's all, you'll have ANBU.dll on your release folder.

## Testing ANBU

ANBU doesn't have any special flag to use for the moment so you can run ANBU as any PIN tool:

```shell
pin -t ANBU.dll -- program_to_unpack.exe
```

Also there's a flag to modify output file name with log.

## Unpacked code

ANBU dumps two different things, one of the things ANBU dumps are memory chunks that appears from unpacking process, this is not a PE file it's only a binary file with written and executed code (can be a complete section or only a chunk from unpacking process), after the unpacking process ANBU will try to dump the unpacked PE file with a new section of imports (called ".F9" I don't have much imagination). For the process a file log is created and updated during the execution.

## Packers tested

I'm not professional on this, but I give some examples to the people who wanna try ANBU those are:

- UPX
- AHPack
- MEW
- EZIP
- FSG
- Mpress
- Basic RunPE
- Test

Test folder is where I save some code tests for testing ANBU, so for example you can find here the test for timing hooks.

## Issues

- A friend has discovered an issue I had when I was compiling PIN with all this stuff of WINDOWS. I had a problem compiling, so I modified Windows.h from PIN (<pin_path>/extras/crt/include/Windows.h). What I did was to comment the next line:

```Cpp
#include WINDOWS_H_PATH
```

And I wrote the next thing:

```Cpp
//#include WINDOWS_H_PATH
#include <my_path_to_windows_sdk_on_my_computer/sdk_version/um/Windows.h>
```

## Changelog

### Version 0.5 (we will start for this one, why not?)

- Written the base of the unpacker.
- Added two heuristics to unpacking model.
- some packers unpacked and tests done for reliability and stability of the tool.

## ToDO

- Next version should include some new heuristic to detect Microsoft Visual Studio OEP trace.
- Allow user to choose unpacked file name.
- Include a way to unpack crypters by saving decrypted code.

## Special thanks to

- [MZ IAT][2]: For helping me with testing, and also discover an issue.
- [Hasherezade][3]: For her blogpost about Visual Studio PIN projects compiling.
- [Joxean Koret][4]: For his blogpost about unpacking with PIN.
- [Jurrian Bremer][5]: For his RunPE unpacking module.
- [Arancino Project][6]: For their heuristics ideas and dynamic protection framework.
- [Dennis Andriesse][7]: For his book Practical Binary Analysis which helped me to start this project.

[1]: <https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads> "Intel PIN download link"
[2]: <https://twitter.com/MZ_IAT> "MZ IAT Twitter"
[3]: <https://twitter.com/hasherezade> "Hasherezade Twitter"
[4]: <https://twitter.com/matalaz> "Joxean Koret Twitter"
[5]: <https://twitter.com/skier_t> "Jurrian Bremer Twitter"
[6]: <https://github.com/necst/arancino> "Arancino Project"
[7]: <https://syssec->mistakenot.net/> "Dennis Andriesse webpage"
