#!/usr/bin/env python3
"""
Process a log file to a more managable form
"""

import argparse
import re

# Pre-compile regular expressions used
color_matcher = re.compile('\x1b\[\d+m')
token_matcher = re.compile('^(?P<lev>\w+)\s+\| (?P<ts>[0-9\-\:\,\s]+) \| MEGATEST \| (?P<token>\w+): (?P<msg>.+)')

# Helper functions
def strip_colors(l):
    """
    Remove ANSI color escape sequences
    """
    return color_matcher.sub('', l)

def extract_traceback(f):
    """
    Pass a file object pointing to start of a traceback
    """
    tb = []
    while True:
        l = next(f).rstrip()
        tb.append(l)
        if not l.startswith('  '):
            break
    return tb

class Package:
    def __init__(self, name):
        self.binaries = {}
        self.name = name

    def get_binary(self, name):
        if name not in self.binaries:
            self.binaries[name] = Binary(name)
        return self.binaries[name]

# Global list of packages (in case there are multiple concatenated in a log)
packages = {}
def get_package(name):
    if name not in packages:
        packages[name] = Package(name)
    return packages[name]

class Binary:
    def __init__(self, name):
        self.name                      = name
        self.functions                 = {}
        self.elf_opened_successfully   = False
        self.dbg_opened_successfully   = False
        self.symbols_read_successfully = False
        self.load_timed_out            = False
        self.cfg_generated             = False
        self.cfg_timed_out             = False
        self.tb                        = []

    def get_func(self, name, addr):
        if name not in self.functions:
            self.functions[name] = Function(name, addr)
        return self.functions[name]

    def elf_open_fail(self, tb):
        self.elf_opened_successfully = False
        self.tb = tb

    def elf_open_success(self, tb):
        self.elf_opened_successfully = True
        self.tb = tb

    def dbg_open_fail(self, tb):
        self.dbg_opened_successfully = False
        self.tb = tb

    def dbg_open_success(self, tb):
        self.dbg_opened_successfully = True
        self.tb = tb

    def symbols_fail(self, tb):
        self.symbols_read_successfully = False
        self.tb = tb

    def symbols_success(self, tb):
        self.symbols_read_successfully = True
        self.tb = tb

    def load_timeout(self, tb):
        self.load_timed_out = True
        self.tb = tb

    def cfg_fail(self, tb):
        self.cfg_generated = False
        self.tb = tb

    def cfg_success(self, tb):
        self.cfg_generated = True
        self.tb = tb

    def cfg_timeout(self, tb):
        self.cfg_timed_out = True
        self.tb = tb


class Function:
    def __init__(self, name, addr):
        self.name                     = name
        self.addr                     = addr
        self.function_present_in_cfg  = False
        self.decompilation_successful = False
        self.codegen_failed           = False
        self.codegen_none_present     = False
        self.decompilation_timed_out  = False
        self.tb                       = []

    def function_present_fail(self, tb):
        self.function_present_in_cfg = False
        self.tb = tb

    def function_present_success(self, tb):
        self.function_present_in_cfg = True
        self.tb = tb

    def decompiler_fail(self, tb):
        self.decompilation_successful = False
        self.tb = tb

    def decompiler_success(self, tb):
        self.decompilation_successful = True
        self.tb = tb

    def codegen_fail(self, tb):
        self.codegen_failed = True
        self.tb = tb

    def codegen_warning(self, tb):
        self.codegen_none_present = True
        self.tb = tb

    def decompiler_timeout(self, tb):
        self.decompilation_timed_out = True
        self.tb = tb


def process_log(path):
    """
    Process an individual log file created during analysis of a package

    Logs are generated on a per-package basis, but this script also handles the
    case where there are data for multiple packages in a single log.
    
    The information we are interested in extracting
    from the logs are:
    - Which package was analyzed?
    - Which package binaries were analyzed?
        - Was the binary successfully loaded?
        - Were the binary debug symbols successfully loaded?
        - Was the CFG successfully created?
        - What was the CFG creation time?
        - How many functions were found in the debug symbols?
        - How many functions were also found in the CFG?
        - How many functions were successfully decompiled?
        - What was the average decompilation time?
    
    Logs consist of event markers, tracebacks, and various debug output. We grep
    through to find the event markers. These can be:
    
    - If the main ELF binary is successfully loaded, or not
      ELF_OPEN_FAIL: elf={elf_path} pkg={pkg_name}
      ELF_OPEN_SUCCESS: elf={elf_path} pkg={pkg_name}

    - If the debug symbols binary is successfully loaded, or not
      DBG_OPEN_FAIL: dbg={dbg_path} pkg={pkg_name}
      DBG_OPEN_SUCCESS: elf={elf_path} pkg={pkg_name}

    - If the symbols were recovered or not
      SYMBOLS_FAIL: elf={elf_path} dbg={dbg_path} pkg={pkg_name}
      SYMBOLS_SUCCESS: elf={elf_path} pkg={pkg_name}

    - If a timeout occurs, this warning is created
      LOAD_TIMEOUT

    - Whether the CFG was successfully created, or not
      CFG_FAIL: elf={elf_path} pkg={pkg_name}
      CFG_SUCCESS: elf={elf_path} pkg={pkg_name}
      CFG_TIMEOUT

    - If a timeout occurs during loading or CFG creation
      ELF_TIMEOUT: elf={_elf_path} dbg={_dbg_path} pkg={_pkg_name}

    (id_str = function={s} address={hex(a)} progress={i}/{len(symbols)} elf={elf_path} dbg={dbg_path} pkg={pkg_name})
    - Whether a function is present in the CFG (as identified by address)
      FUNCTION_PRESENT_FAIL: {id_str}
      FUNCTION_PRESENT_SUCCESS: {id_str}

    - Whether the decompiler successfully decompiled the function and generated
      source code, or not
      DECOMPILER_FAIL: {id_str}
      CODEGEN_FAIL: {id_str}
      CODEGEN_WARNING: 'None': present {id_str}
      DECOMPILER_SUCCESS: {id_str}
      DECOMPILER_TIMEOUT: {id_str}

    - Final report
      RESULTS: elf={_elf_path} dbg={_dbg_path} pkg={_pkg_name} reasons={reasons}
    """
    last_ts = None
    with open(path, 'r') as f:
        for line in f:
            if not (line.startswith('INFO') or line.startswith('WARNING') or line.startswith('ERROR')):
                continue

            # Sanitize the line
            line = strip_colors(line.strip())
            # print(line)

            # Match token pattern
            m = token_matcher.match(line)
            if not m: continue
            lev, ts, token, msg = m.groups()

            # Handle individual tokens
            def get_field(name):
                # Note: Breaks for 'reasons' field due to spaces
                m = re.findall(name + '\=([^\s]+)', msg)
                return m[0] if len(m) > 0 else ''

            # These are always part of a token
            pkg = get_package(get_field('pkg'))
            elf = pkg.get_binary(get_field('elf'))

            elf_toks = {
                'ELF_OPEN_FAIL':    Binary.elf_open_fail,
                'ELF_OPEN_SUCCESS': Binary.elf_open_success,
                'DBG_OPEN_FAIL':    Binary.dbg_open_fail,
                'DBG_OPEN_SUCCESS': Binary.dbg_open_success,
                'SYMBOLS_FAIL':     Binary.symbols_fail,
                'SYMBOLS_SUCCESS':  Binary.symbols_success,
                'LOAD_TIMEOUT':     Binary.load_timeout,
                'CFG_FAIL':         Binary.cfg_fail,
                'CFG_SUCCESS':      Binary.cfg_success,
                'CFG_TIMEOUT':      Binary.cfg_timeout,
                # 'ELF_TIMEOUT' (encompases all above, cannot continue)
            }

            tb = []
            if token.endswith('_FAIL'):
                line = next(f)
                if line.startswith('Traceback'):
                    tb = extract_traceback(f)

            # Loading ELF/Debug
            if token in elf_toks:
                elf_toks[token](elf, tb)

            func_toks = {
                'FUNCTION_PRESENT_FAIL':    Function.function_present_fail,
                'FUNCTION_PRESENT_SUCCESS': Function.function_present_success,
                'CODEGEN_FAIL':             Function.codegen_fail,
                'CODEGEN_WARNING':          Function.codegen_warning,
                'DECOMPILER_SUCCESS':       Function.decompiler_success,
                'DECOMPILER_FAIL':          Function.decompiler_fail,
                'DECOMPILER_TIMEOUT':       Function.decompiler_timeout,
                }

            if token in func_toks:
                func = elf.get_func(get_field('function'), get_field('address'))
                func_toks[token](func, tb)

            last_ts = ts

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    args = ap.parse_args()
    process_log(args.log)
    def print_tb(tb):
        print('\n'.join(tb))
    for pkg_name in packages:
        pkg = packages[pkg_name]
        print('Package: ' + pkg.name)
        for bin_name in pkg.binaries:
            bin = pkg.binaries[bin_name]
            if not bin.elf_opened_successfully:
                print('Failed to open binary')
                print_tb(bin.tb)
                continue
            elif not bin.dbg_opened_successfully:
                print('Failed to open debug symbols')
                print_tb(bin.tb)
                continue
            elif not bin.cfg_generated:
                print('Failed to generate CFG')
                print_tb(bin.tb)
                continue

            print('  Binary: ' + bin.name)
            for func_name in bin.functions:
                func = bin.functions[func_name]
                print('    Function: ' + func.name)
                print('      In CFG? %s' % ('Yes' if func.function_present_in_cfg else 'No'))
                if not func.function_present_in_cfg:
                    continue
                print('      Decompiled? %s' % ('Yes' if func.decompilation_successful else 'No'))
                if not func.decompilation_successful:
                    if func.decompilation_timed_out:
                        print('        Timed Out')
                    else:
                        print('---- Traceback:')
                        print_tb(func.tb)
                        print('----\n\n')

if __name__ == '__main__':
    main()
