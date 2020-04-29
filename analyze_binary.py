#!/usr/bin/env python

#pylint:disable=broad-except,logging-fstring-interpolation

import argparse
import contextlib
import logging
import sys
from typing import Optional

import stopit

import angr

for some_logger in [ logging.getLogger(name) for name in logging.root.manager.loggerDict ]:
    some_logger.setLevel(logging.CRITICAL)

l = logging.getLogger('MEGATEST')
l.setLevel('INFO')

class Abort(Exception): pass

@contextlib.contextmanager
def catcher(s, stop=True):
    try:
        yield
    except stopit.utils.TimeoutException:
        raise
    except Exception:
        awesome_error(s, exc_info=True)
        if stop:
            raise Abort()

reasons = { }

def awesome_log(lvl, msg, **kwargs):
    l.log(lvl, msg, **kwargs)
    reason = msg.split(":")[0]
    reasons.setdefault(reason, 0)
    reasons[reason] += 1

def awesome_info(msg, **kwargs):
    awesome_log(logging.INFO, msg, **kwargs)
def awesome_warning(msg, **kwargs):
    awesome_log(logging.WARNING, msg, **kwargs)
def awesome_error(msg, **kwargs):
    awesome_log(logging.ERROR, msg, **kwargs)


class Timeout:
    def __init__(self, n):
        self.n = n

    def __enter__(self):
        if sys.platform.startswith("win"):
            return self
        return stopit.SignalTimeout(self.n).__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


def _doit_core(elf, elf_path: str, pkg_name: str, dbg_path: Optional[str]):
    if pkg_name is None:
        pkg_name = "<standalone>"

    # Build CFG
    with catcher(f"CFG_FAIL: elf={elf_path} pkg={pkg_name}"):
        cfg = elf.analyses.CFG(data_references=True, cross_references=True, normalize=True)
        awesome_info(f"CFG_SUCCESS: elf={elf_path} pkg={pkg_name}")

    # ignore PLTs, alignments, and SimProcedures
    funcs = [ func for func in cfg.functions.values()
              if not func.is_plt
              and not func.is_simprocedure
              and not func.alignment
              ]

    # full-program calling convention analysis with variable recovery
    with Timeout(30) as t:
        with catcher(f"CC_FAIL: elf={elf_path}, pkg={pkg_name} dbg={dbg_path}"):
            elf.analyses.CompleteCallingConventions(recover_variables=True)
            awesome_info(f"CC_SUCCESS: elf={elf_path}, pkg={pkg_name} dbg={dbg_path}")

    for i, func in enumerate(funcs):
        id_str = f"function={func.name} address={hex(func.addr)} progress={i}/{len(funcs)} elf={elf_path} dbg={dbg_path} pkg={pkg_name}"
        with Timeout(5) as t:
            with catcher(f"DECOMPILER_FAIL: {id_str}", stop=False):
                decompilation = elf.analyses.Decompiler(func, cfg=cfg)
                with catcher(f"CODEGEN_FAIL: {id_str}", stop=False):
                    text = decompilation.codegen.text
                    assert text
                    if "None" in text:
                        awesome_warning(f"CODEGEN_WARNING: 'None': present {id_str}")
                    awesome_info(f"DECOMPILER_SUCCESS: {id_str}")
        if not t:
            awesome_warning(f"DECOMPILER_TIMEOUT: {id_str}")

    return cfg


@stopit.signal_timeoutable(default="TIMEOUT")
def doit_raw(elf_path, pkg_name=None):
    if pkg_name is None:
        pkg_name = "<standalone>"

    with catcher(f"ELF_OPEN_FAIL: elf={elf_path} pkg={pkg_name}"):
        elf = angr.Project(elf_path, auto_load_libs=False, load_debug_info=True)
        awesome_info(f"ELF_OPEN_SUCCESS: elf={elf_path} pkg={pkg_name}")

    _doit_core(elf, elf_path, pkg_name, None)


@stopit.signal_timeoutable(default="TIMEOUT")
def doit_raw_with_symbols(elf_path, pkg_name=None, dbg_path=None):
    if pkg_name is None:
        pkg_name = "<standalone>"

    with catcher(f"ELF_OPEN_FAIL: elf={elf_path} pkg={pkg_name}"):
        elf = angr.Project(elf_path, auto_load_libs=False, load_debug_info=True)
        awesome_info(f"ELF_OPEN_SUCCESS: elf={elf_path} pkg={pkg_name}")

    if dbg_path:
        # Load symbols from the dbg file
        with catcher(f"DBG_OPEN_FAIL: dbg={dbg_path} pkg={pkg_name}"):
            dbg = angr.Project(dbg_path, auto_load_libs=False)
            awesome_info(f"DBG_OPEN_SUCCESS: elf={elf_path} pkg={pkg_name}")

        with catcher(f"SYMBOLS_FAIL: elf={elf_path} dbg={dbg_path} pkg={pkg_name}"):
            symbols = [ (s.name, s.rebased_addr) for s in dbg.loader.symbols if not s.is_import and s.is_function ]
            awesome_info(f"SYMBOLS_SUCCESS: elf={elf_path} pkg={pkg_name}")
    else:
        # Load symbols from the ELF file
        with catcher(f"SYMBOLS_FAIL: elf={elf_path} pkg={pkg_name}"):
            symbols = [ (s.name, s.rebased_addr) for s in elf.loader.symbols if not s.is_import and s.is_function ]
            awesome_info(f"SYMBOLS_SUCCESS: elf={elf_path} pkg={pkg_name}")

    if not symbols:
        awesome_info(f"SYMBOLS_FAIL: No symbol available. elf={elf_path} pkg={pkg_name} dbg={dbg_path}")
        return

    cfg = _doit_core(elf, elf_path, pkg_name, dbg_path)

    l.info("Checking functions...")
    for i, (s, a) in enumerate(symbols):
        id_str = f"function={s} address={hex(a)} progress={i}/{len(symbols)} elf={elf_path} dbg={dbg_path} pkg={pkg_name}"
        if a in cfg.functions:
            awesome_info(f"FUNCTION_PRESENT_SUCCESS: {id_str}")
        else:
            awesome_warning(f"FUNCTION_PRESENT_FAIL: {id_str}")
            continue


def doit(pkg_name, elf_path, dbg_path, use_symbols, timeout=3600):
    try:
        if use_symbols:
            return doit_raw_with_symbols(elf_path, pkg_name=pkg_name, dbg_path=dbg_path, timeout=timeout)  #pylint:disable=unexpected-keyword-arg
        else:
            return doit_raw(elf_path, pkg_name=pkg_name)
    except Abort:
        return None
    except Exception:
        awesome_error("MYSTERY_FAIL: elf={elf_path} dbg={dbg_path} pkg={pkg_name}", exc_info=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=str, help="Path to the binary file.")
    parser.add_argument("--package", type=str, help="Package name or URL.", default=None)
    parser.add_argument("--use-symbols", action="store_true", help="Should debug symbols be used to verify functions.",
                        default=False)
    parser.add_argument("--dbg", type=str, help="Path to the debug symbol file.", default=None)
    args = parser.parse_args()

    _pkg_name = args.package
    _elf_path = args.binary
    _use_symbols = args.use_symbols
    _dbg_path = args.dbg

    if doit(_pkg_name, _elf_path, _dbg_path, _use_symbols) == "TIMEOUT":
        awesome_error(f"ELF_TIMEOUT: elf={_elf_path} dbg={_dbg_path} pkg={_pkg_name}")
    l.info(f"RESULTS: elf={_elf_path} dbg={_dbg_path} pkg={_pkg_name} reasons={reasons}")


if __name__ == '__main__':
    main()
