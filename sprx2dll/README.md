# SPRX to DLL

Some SPRX (Signed Playstation Relocatable eXecutable) files inside the PlayStation 5, are written using the [Mono](https://www.mono-project.com/) .Net framework, so the code is actually generated inside a DLL file and loaded by the ELF at runtime.

This script automatize the DLL extraction from this executables by parsing the ELF symbols until find a specific NID, (N)ame(ID)entifiers, from the `dll_start` symbol, and them extracting the DLL inside the ELF file.


## Install

In order to use, you just need to install the dependencies with `pipenv`.

```
pip install pipenv
git clone https://github.com/buzzer-re/ps_scripts.git
cd ps_scripts/sprx2dll
pipenv shell && pipenv sync
```
## Usage

```
$ python sprx2dll.py -h
usage: Extract embedded DLL files from PS5 SPRX (Signed Shared Library) files

positional arguments:
  SPRX

options:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Output filename, default: filename.dl
```

## Example

```
$ python sprx2dll.py Sce.Vsh.Theme.dll.sprx
[+] Loading Sce.Vsh.Theme.dll.sprx... [+]
[+] Found dll_start symbol, extracting PE... [+]
[+] PE is at virtual address 0x34050, extracting... [+]
[+] Saving as Sce.Vsh.Theme.dll [+]
[+] Done! [+]
```


In order to get the executables, you need to decrypt the executables from your OWN console, most .Net programs are are located at `/system_ex/common_ex/lib`


## Resources

- [SELF-SPRX](https://psdevwiki.com/ps3/SELF_-_SPRX)
- [NID](https://www.youtube.com/watch?v=xxKNxdulGq0)
