#!/usr/bin/env python3

import argparse
import os
import subprocess
from macholib import MachO


CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_I386 = 7
CPU_TYPE_ARM = 12
CPU_TYPE_X86_64 = (CPU_TYPE_I386 | CPU_ARCH_ABI64)
CPU_TYPE_ARM64 = (CPU_TYPE_ARM | CPU_ARCH_ABI64)

CPU_SUBTYPE_ARM_ALL = 0
CPU_SUBTYPE_ARM_V7 = 9  # ARMv7-A and ARMv7-R
CPU_SUBTYPE_ARM_V7S = 11  # Swift

CPU_SUBTYPE_ARM64_ALL = 0
CPU_SUBTYPE_ARM64E = 2

CPU_SUBTYPE_ARM64_PTR_AUTH_MASK = 0x0f000000

LC_VERSION_MIN_IPHONEOS = 0x25
LC_BUILD_VERSION = 0x32

class MachOFile:
    def __init__(self, path):
        self.path = path
        self.macho = MachO.MachO(self.path)

    def headers(self):
        headers = []
        for header in self.macho.headers:
            headers.append(MachOHeader(header))

        return headers

    def archs(self):
        archs = []
        for macho_header in self.headers():
            archs.append(macho_header.arch())

        return archs


class MachOHeader:
    def __init__(self, header):
        self.header = header

    def get_load_commands(self, lc):
        return list(filter(lambda x: x[0].cmd == lc, self.header.commands))

    def get_verion_min_command(self):
        lcs = self.get_load_commands(LC_VERSION_MIN_IPHONEOS)
        if len(lcs) > 0:
            return lcs[0][1]

        return None

    def get_build_version_command(self):
        lcs = self.get_load_commands(LC_BUILD_VERSION)
        if len(lcs) > 0:
            return lcs[0][1]

        return None

    def get_sdk(self):
        if self.get_verion_min_command():
            return MachOHeader.apple_version(self.get_verion_min_command().sdk)
        elif self.get_build_version_command():
            return MachOHeader.apple_version(self.get_build_version_command().sdk)
        else:
            return None

    def get_minos(self):
        if self.get_verion_min_command():
            return MachOHeader.apple_version(self.get_verion_min_command().version, True)
        elif self.get_build_version_command():
            return MachOHeader.apple_version(self.get_build_version_command().minos, True)
        else:
            return None

    @staticmethod
    def apple_version(version, zeros=False):
        major = version >> 16
        minor = version >> 8 & 0xff
        update = version & 0xff

        components = [major]
        if update > 0:
            components.extend([minor, update])
        elif minor > 0:
            components.append(minor)
        elif zeros:
            components.append(minor)

        return '.'.join(map(lambda x: str(x), components))

    def arch(self):
        type = self.header.header.cputype
        subtype = self.header.header.cpusubtype

        if type == CPU_TYPE_ARM:
            if subtype == CPU_SUBTYPE_ARM_V7:
                return 'armv7'
            elif subtype == CPU_SUBTYPE_ARM_V7S:
                return 'armv7s'
            else:
                return None
        elif type == CPU_TYPE_ARM64:
            if subtype == CPU_SUBTYPE_ARM64_ALL:
                return 'arm64'
            elif subtype & CPU_SUBTYPE_ARM64_PTR_AUTH_MASK >> 24 == CPU_SUBTYPE_ARM64E:
                return 'arm64e'
            else:
                return None
        elif type == CPU_TYPE_I386:
            return 'i386'
        elif type == CPU_TYPE_X86_64:
            return 'x86_64'
        else:
            return None


def find_macho_binaries(paths):
    macho_binaries = []
    for path in paths:
        try:
            macho = MachOFile(path)
            macho_binaries.append(macho)
        except:
            pass

    return macho_binaries


def remove_binary_archs(macho_binary, remove_archs, quiet=True):
    archs = get_archs(macho_binary)

    remove_flags = []
    for remove_arch in remove_archs:
        if remove_arch in archs:
            remove_flags.append(f"-remove {remove_arch}")

    if len(remove_flags) > 0:
        lipo_cmd = f"xcrun lipo {' '.join(remove_flags)} -output {macho_binary} {macho_binary}"
        if not quiet:
            print(lipo_cmd)
        subprocess.call(lipo_cmd, shell=True)


def main():
    parser = argparse.ArgumentParser(description='Strip architectures from Mach-Os in a folder')
    parser.add_argument('--path', dest='path',
                        help='path to .app, binary or folder', required=True)
    parser.add_argument('--remove', dest='remove_archs', nargs='*',
                        help='Remove the architecture')
    parser.add_argument('--filter', dest='filter_archs', nargs='*',
                        help='Filter on the architecture')
    parser.add_argument('--thin', dest='thin_arch',
                        help='Thin, keep only the specified architecture')
    parser.add_argument('--verify', dest='validate_arch',
                        help='Require an architecture to be present in the Mach-O')
    parser.add_argument('-r', '--recursive', dest='recurse', action='store_true',
                        help='Recurse into subdirectories')
    parser.add_argument('--quiet', dest='quiet', action='store_true',
                        help='Be quiet')
    args = parser.parse_args()

    paths = []
    if args.recurse:
        directory = os.path.abspath(args.path.lstrip('\'').rstrip('\''))
        for folder, subs, files in os.walk(directory):
            for file in files:
                path = os.path.join(folder, file)
                paths.append(path)
    else:
        paths.append(args.path)

    macho_binaries = find_macho_binaries(paths)
    for macho_binary in macho_binaries:
        macho_binary_display = os.path.relpath(macho_binary.path)

        validate_arch = args.validate_arch
        if validate_arch and validate_arch not in macho_binary.archs():
            print(f"{macho_binary_display} missing {validate_arch}")

        thin_arch = args.thin_arch
        if thin_arch:
            remove_archs = list(set(macho_binary.archs()) - {thin_arch})
        else:
            remove_archs = args.remove_archs

        if remove_archs:
            remove_binary_archs(macho_binary, remove_archs, args.quiet)

    macho_binaries = find_macho_binaries(paths)
    for macho_binary in macho_binaries:
        # sdk = get_sdk(macho_binary)
        if not args.quiet:
            macho_binary_display = os.path.relpath(macho_binary.path, directory)
            print(f"{macho_binary_display}")
            for header in macho_binary.headers():
                arch = header.arch()
                if args.filter_archs and arch not in args.filter_archs:
                    continue
                sdk = header.get_sdk()
                minos = header.get_minos()
                print(f" - {arch} - sdk: {sdk}, minos: {minos}")


if __name__ == '__main__':
    main()
