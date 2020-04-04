#!/usr/bin/env python3
"""
Process a log file to a more managable form
"""

import argparse
import re
import os
from jinja2 import Environment, FileSystemLoader
import datetime
now = datetime.datetime.now().strftime('%c')

# Pre-compile regular expressions used
color_matcher = re.compile(r'\x1b\[\d+m')
token_matcher = re.compile(r'^(?P<lev>\w+)\s+\| (?P<ts>[0-9\-\:\,\s]+) \| MEGATEST \| (?P<token>\w+): (?P<msg>.+)')
arch_matcher  = re.compile(r'_(\w+).deb$')

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

class Summary:
    def __init__(self, packages):
        self.packages = packages

        self.num_packages = 0
        self.num_binaries = 0
        self.num_binaries_failed_to_open = 0
        self.num_binaries_dbg_failed_to_open = 0
        self.num_binaries_load_timed_out = 0
        self.num_binaries_load_errored_out = 0
        self.num_binaries_cfg_timed_out = 0
        self.num_binaries_cfg_errored_out = 0
        self.num_binaries_loaded = 0
        self.num_functions = 0
        self.num_functions_not_present_in_cfg = 0
        self.num_functions_not_decompiled = 0
        self.num_functions_decompilation_timeout = 0
        self.num_functions_decompilation_errored_out = 0
        self.num_functions_decompiled = 0
        self.top_error = ''
        self.top_error_count = 0
        self.top_error_tb = ''

        for pkg_name in self.packages:
            self.num_packages += 1
            pkg = packages[pkg_name]
            for bin_name in pkg.binaries:
                self.num_binaries += 1
                bin = pkg.binaries[bin_name]

                if bin.elf_timed_out:
                    if not bin.elf_opened_successfully:
                        # Binary failed to open with timeout
                        self.num_binaries_failed_to_open += 1
                    elif not bin.dbg_opened_successfully:
                        # Debug symbols failed to open with timeout
                        self.num_binaries_dbg_failed_to_open += 1

                    if bin.dbg_opened_successfully:
                        # Timed out during CFG generation
                        self.num_binaries_cfg_timed_out += 1
                    else:
                        # Timed out during load
                        self.num_binaries_load_timed_out += 1

                    continue

                # Did not timeout

                if not bin.elf_opened_successfully:
                    # Error during loading of ELF
                    self.num_binaries_load_errored_out += 1
                    self.num_binaries_failed_to_open += 1
                    continue
                elif not bin.dbg_opened_successfully:
                    # Error during loading of debug symbols
                    self.num_binaries_load_errored_out += 1
                    self.num_binaries_dbg_failed_to_open += 1
                    continue
                elif not bin.cfg_generated:
                    # Error during CFG creation
                    self.num_binaries_cfg_errored_out += 1
                    continue

                self.num_binaries_loaded += 1

                for func_name in bin.functions:
                    self.num_functions += 1
                    func = bin.functions[func_name]
                    if not func.function_present_in_cfg:
                        self.num_functions_not_present_in_cfg += 1
                        continue
                    if not func.decompilation_successful:
                        self.num_functions_not_decompiled += 1
                        if func.decompilation_timed_out:
                            self.num_functions_decompilation_timeout += 1
                        else:
                            self.num_functions_decompilation_errored_out += 1
                    else:
                        self.num_functions_decompiled += 1

    def get_summary(self, indent):
        s = ''
        s += ' '*indent + 'num_packages:                     %d\n' % (self.num_packages)
        s += ' '*indent + 'num_binaries:                     %d\n' % (self.num_binaries)
        if self.num_binaries > 0:
            s += ' '*indent + 'num_binaries_load_errored_out:    %d (%f%%)\n' % (self.num_binaries_load_errored_out, 100.0*self.num_binaries_load_errored_out/self.num_binaries)
            s += ' '*indent + 'num_binaries_load_timed_out:      %d (%f%%)\n' % (self.num_binaries_load_timed_out, 100.0*self.num_binaries_load_timed_out/self.num_binaries)
            s += ' '*indent + 'num_binaries_cfg_errored_out:     %d (%f%%)\n' % (self.num_binaries_cfg_errored_out, 100.0*self.num_binaries_cfg_errored_out/self.num_binaries)
            s += ' '*indent + 'num_binaries_cfg_timed_out:       %d (%f%%)\n' % (self.num_binaries_cfg_timed_out, 100.0*self.num_binaries_cfg_timed_out/self.num_binaries)
            s += ' '*indent + 'num_binaries_loaded:              %d (%f%%)\n' % (self.num_binaries_loaded, 100.0*self.num_binaries_loaded/self.num_binaries)
        s += ' '*indent + 'num_functions:                    %d\n' % (self.num_functions)
        if self.num_functions > 0:
            s += ' '*indent + 'num_functions_not_present_in_cfg: %d (%f%%)\n' % (self.num_functions_not_present_in_cfg, 100.0*self.num_functions_not_present_in_cfg/self.num_functions)
            s += ' '*indent + 'num_functions_not_decompiled:     %d (%f%%)\n' % (self.num_functions_not_decompiled, 100.0*self.num_functions_not_decompiled/self.num_functions)
            s += ' '*indent + 'num_functions_decompiled:         %d (%f%%)\n' % (self.num_functions_decompiled, 100.0*self.num_functions_decompiled/self.num_functions)
        return s

    def determine_top_error(self):
        print('Determining top error...')
        errors_sample_tb = {}
        errors = {}
        for pkg_name in self.packages:
            pkg = self.packages[pkg_name]
            for bin_name in pkg.binaries:
                bin = pkg.binaries[bin_name]
                if not bin.cfg_generated: continue
                print('  Binary: ' + bin.name)
                for func_name in bin.functions:
                    func = bin.functions[func_name]
                    if not func.function_present_in_cfg or func.decompilation_timed_out or func.decompilation_successful:
                        continue
                    if len(func.tb) == 0:
                        print('Warning: Error in decompilation without traceback?\n\t%s\n\t%s\n\t%s' % (pkg_name, bin_name, func_name))
                        continue
                    err = func.tb[-1].strip()
                    if err not in errors:
                        errors_sample_tb[err] = func.tb
                        errors[err] = 0
                    errors[err] += 1

        for err in errors:
            if errors[err] > self.top_error_count:
                self.top_error_count = errors[err]
                self.top_error = err
                self.top_error_tb = '\n'.join(errors_sample_tb[err])

    def print_console_report(self):
        for pkg_name in self.packages:
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
                            print_tb('\n'.join(func.tb))
                            print('----\n\n')

class Package:
    def __init__(self, name):
        self.binaries = {}
        self.name = name
        self.arch = arch_matcher.findall(name)[-1]

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
        self.cfg_generated             = False
        self.elf_timed_out             = False
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

    def cfg_fail(self, tb):
        self.cfg_generated = False
        self.tb = tb

    def cfg_success(self, tb):
        self.cfg_generated = True
        self.tb = tb

    def elf_timeout(self, tb):
        self.elf_timed_out = True
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
                'CFG_FAIL':         Binary.cfg_fail,
                'CFG_SUCCESS':      Binary.cfg_success,
                'ELF_TIMEOUT':      Binary.elf_timeout
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
        print(''.join(tb))

    # Overall summary for the entire run
    print('Overall')
    overall_summary = Summary(packages)
    print(overall_summary.get_summary(indent=2))
    overall_summary.determine_top_error()

    # Setup Jinja2 template environment
    env = Environment(loader=FileSystemLoader(searchpath='templates'))

    # Group packages by architecture for arch-specific breakdown
    pkg_by_arch = {}
    for pkg_name in packages:
        pkg = packages[pkg_name]
        if pkg.arch not in pkg_by_arch:
            pkg_by_arch[pkg.arch] = {}
        pkg_by_arch[pkg.arch][pkg.name] = pkg

    # Summarize results for each architecture
    summary_by_arch = {}
    for arch_name in pkg_by_arch:
        print('Architecture %s: %d package(s)' % (arch_name, len(pkg_by_arch[arch_name])))
        summary = Summary(pkg_by_arch[arch_name])
        print(summary.get_summary(indent=2))
        summary_by_arch[arch_name] = summary
        summary.determine_top_error()

    # Generate index
    output_page_path = os.path.join('.', 'index.html')
    template = env.get_template('template.html')
    open(output_page_path, 'w').write(template.render(**locals(), **globals()))

if __name__ == '__main__':
    main()
