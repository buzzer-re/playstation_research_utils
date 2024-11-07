import lief
import argparse
import os, sys


def log_error(msg: str):
    print(f"[-] {msg} [-]")

def log(msg: str):
    print(f"[+] {msg} [+]") 


# This is the dll_start GOT symbol NID
DLL_START_NID = "Tkla3v2SbEs#C#A" 

if __name__ == '__main__':
    lief.logging.set_level(lief.logging.LEVEL.CRITICAL) # Disable warning

    parser = argparse.ArgumentParser("sprx2dll", "Extract embedded DLL files from PS5 SPRX (Signed Shared Library) files")
    parser.add_argument("SPRX")
    parser.add_argument("--output", "-o", help="Output filename, default: filename.dll", default='')
    
    args = parser.parse_args()

    target = args.SPRX
    output = args.output

    if not os.path.exists(target):
        log_error(f"File {target} does not exist!")
        sys.exit(1)

    raw_data = None

    with open(target, "rb") as raw:
        raw_data = raw.read()

    log(f"Loading {target}...")

    sprx: lief.Binary.FORMATS.ELF = lief.parse(raw_data)
    symbol = sprx.get_symbol(DLL_START_NID)
    
    if not symbol:
        log_error("Unable to find dll_start symbol!")
        sys.exit(1)
    
    log("Found dll_start symbol, extracting PE...")

    segment = sprx.segment_from_virtual_address(symbol.value)
    
    pe_addr = segment.virtual_address + (symbol.value - segment.virtual_address)
    log(f"PE is at virtual address {hex(pe_addr)}, extracting...")
    pe_content =  segment.content[(symbol.value - segment.virtual_address):].tobytes() # This is a memoryview object, not a list
    
    if not output:
        if target.endswith(".dll.sprx"):
            output = target[:-5]
        else:
            output = f"{target}.dll"
    
    log(f"Saving as {output}")
    
    with open(output, "wb") as out:
        out.write(pe_content)
    
    log("Done!")
