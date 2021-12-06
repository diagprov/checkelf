#!/usr/bin/env python3

import argparse
import hashlib
import os
import sys
import json

from enum import Enum
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

class MitRelRO(Enum):
    NONE = 0
    PARTIAL = 1
    FULL = 2

RelRo = {MitRelRO.NONE: 'none',
         MitRelRO.PARTIAL: 'partial',
         MitRelRO.FULL: 'full'}

class MitPIE(Enum):
    NOT_PIE = 0
    PIE = 1

class MitCanary(Enum):
    UNKNOWN = 0
    NO = 1
    YES = 1

class MitNX(Enum):
    NO = 0
    YES = 1

class MitFortify(Enum):
    NO = 0
    YES = 1

class LinkType(Enum):
    STATIC = 1
    DYNAMIC = 2

class Compiler(Enum):
    UNKNOWN = 0
    GCC = 1
    CLANG = 2
    ICC = 3
    GHC = 4
    GNAT = 5
    GO = 6
    RUSTC = 7

CompilerFamily = {Compiler.UNKNOWN: 'Unknown',
                  Compiler.GCC: 'GCC',
                  Compiler.CLANG: 'Clang',
                  Compiler.ICC: 'Intel C/C++',
                  Compiler.GHC: 'Glasgow Haskell Compiler',
                  Compiler.GNAT: 'GNU Ada Compiler',
                  Compiler.GO: 'Go',
                  Compiler.RUSTC: 'Rustc'}

class Language(Enum):
    UNKNOWN = 0
    C = 1
    CXX = 2
    GO = 3
    RUST = 4
    HASKELL = 5
    OCAML = 6
    ADA = 7

LanguageNames = {Language.UNKNOWN: 'Unknown',
                 Language.C: 'C',
                 Language.CXX: 'C++',
                 Language.GO: 'Go',
                 Language.RUST: 'Rust',
                 Language.HASKELL: 'Haskell',
                 Language.OCAML: 'OCaml',
                 Language.ADA: 'Ada/Spark'}

class Type(Enum):
    Executable = 0
    SharedObject = 1

BUFSIZE = 65536

def _compute_hashes(fileobject):
    fileobject.seek(0, os.SEEK_SET)

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha3_256 = hashlib.sha3_256()

    while True:
        data = fileobject.read(BUFSIZE)
        
        if not data:
            break
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
        sha3_256.update(data)

    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), sha3_256.hexdigest()

class ELFObject(object):

    __elffile__ = None

    def __init__(self, fileobject, path, hashing=True):
        self.path = os.path.abspath(path)
        if hashing:
            self.md5, self.sha1, self.sha256, self.sha3_256 = _compute_hashes(fileobject)
        else:
            self.md5, self.sha1, self.sha256, self.sha3_256 = '','','',''

        self.__elffile__ = ELFFile(fileobject)
        self.__dwarf__ = self.__elffile__.get_dwarf_info()

        self.arch = self.__elffile__.get_machine_arch()
        self.bdwarf = self.__elffile__.has_dwarf_info()
        self.mitigation_relro = MitRelRO.NONE
        self.language = Language.UNKNOWN
        self.entrypoint = self.__elffile__.header.e_entry
        self.libs = []

        self._acquire_section_names()
        self._acquire_segment_types()
        self._acquire_allsyms()
        self._acquire_comment()
        self._acquire_symbols()
        self._acquire_imports()
        self._acquire_libs()
        self._acquire_interpreter()

    def _acquire_section_names(self):
        self.section_names=list(map(lambda x: x.name, self.__elffile__.iter_sections()))

    def _acquire_segment_types(self):
        self.segment_types=set(map(lambda x: x.header.p_type, self.__elffile__.iter_segments()))

    def _acquire_comment(self):
        commentsec = self.__elffile__.get_section_by_name('.comment')
        if commentsec == None:
            self.comments = None
            return

        comments = commentsec.data().decode("utf-8").split("\x00")
        self.comments = list(filter(lambda x: x!='', comments))

    def _acquire_allsyms(self):
        self.symbol_tables = [
            sec for sec in self.__elffile__.iter_sections()
            if isinstance(sec, SymbolTableSection)
        ]
        
    def _acquire_symbols(self):
        symtab = self.__elffile__.get_section_by_name('.symtab')
        if symtab != None:
            self.symbols = list(map(lambda x: x.name, symtab.iter_symbols()))
        else:
            self.symbols = None

    def _acquire_imports(self):
        dynsymtab = self.__elffile__.get_section_by_name('.dynsym')
        if dynsymtab != None:
            self.imports = list(map(lambda x: x.name, dynsymtab.iter_symbols()))
        else:
            self.imports = None

    def elf_read_cstring(self, tablepos, index):
        e = self.__elffile__
        e.stream.seek(tablepos, os.SEEK_SET)
        e.stream.seek(index, os.SEEK_CUR)

        v = b''
        while True:
            b = e.stream.read(1)
            print(b)
            if ord(b) == 0:
                break
            v += b
        return v

    def _acquire_libs(self):
        ds = self.__elffile__.get_section_by_name('.dynamic')
        if ds == None:
            return
        needed = list(filter(lambda t: t.entry.d_tag == 'DT_NEEDED', ds.iter_tags()))
        stringtables = s_table = list(filter(lambda t: t.entry.d_tag == 'DT_STRTAB', ds.iter_tags()))
        if len(stringtables) != 1:
            print(stringtables)
            raise Exception("Multiple String Tables.")
        stringtable = stringtables[0]
        tablepos = stringtable.entry.d_ptr

        for n in needed:
            if n.__dict__.get('needed'):
                libu = n.needed
            else:
                lib = self.elf_read_cstring(tablepos, n.entry.d_ptr)
                libu = lib.decode("utf-8")
            self.libs.append(libu)

        if len(self.libs) > 0:
            self.lflags = ' '.join(ELFObject.libs_to_links(self.libs))
        else:
            self.lflags = ''

    def _acquire_interpreter(self):
        interp = self.__elffile__.get_section_by_name(".interp")
        if interp == None:
            self.interpreter = ''
            return

        interpreter = interp.data().decode("utf-8").strip("\x00")
        self.interpreter = interpreter

    def checks(self):
        self._check_link()
        self._check_pie()
        self._check_gnu_relro()
        self._check_symbols()
        self._check_canary()
        self._check_stack()
        self._check_fortify()
        self._check_excepttable()
        self._heuristic_ehframe()
        self._heuristic_vtables()
        self._heuristic_compiler()
        self._heuristic_language()

    def _check_link(self):
        self.linktype = LinkType.STATIC if len(self.libs) == 0 else LinkType.DYNAMIC

    def _check_pie(self):
        base_address = next(seg for seg in self.__elffile__.iter_segments()
                                        if seg['p_type'] == "PT_LOAD")['p_vaddr']
        if self.__elffile__['e_type'] == 'ET_DYN' and base_address == 0:
            self.mitigation_pie = MitPIE.PIE
        else:
            self.mitigation_pie = MitPIE.NOT_PIE

    def _check_gnu_relro(self):
        if 'PT_GNU_RELRO' in self.segment_types:
            self.mitigation_relro = MitRelRO.PARTIAL

            dyn=self.__elffile__.get_section_by_name(".dynamic")
            if dyn == None:
                return
            dyntags=list(dyn.iter_tags())
            flags_entry = list(filter(lambda x: x.entry.d_tag == 'DT_FLAGS', dyntags))
            if len(flags_entry) > 0:
                flagsentry = flags_entry[0]
                value = flagsentry.entry.d_val
                if value == 8:
                    self.mitigation_relro = MitRelRO.FULL
            bindnow = list(filter(lambda x: x.entry.d_tag == 'DT_BIND_NOW', dyntags))
            if len(bindnow) > 0:
                self.mitigation_relro = MitRelRO.FULL

    def _check_symbols(self):
        self.bsymbols = self.__elffile__.get_section_by_name('.symtab') != None

    def _check_canary(self):
        if self.bsymbols == False:
            self.mitigation_stackcanary = MitCanary.UNKNOWN
        else:
            if ('__stack_chk_fail' in self.symbols or 
               '__intel_security_cookie' in self.symbols):
                self.mitigation_stackcanary = MitCanary.YES
            else:
                self.mitigation_stackcanary = MitCanary.NO

    def _check_stack(self):
        stacksegs = list(filter(lambda x: x.header.p_type == 'PT_GNU_STACK', self.__elffile__.iter_segments()))
        if len(stacksegs) > 0:
            stackseg = stacksegs[0]
            
            self.mitigation_nx = MitNX.YES if (stackseg.header.p_flags & 1) == 0 else "no"
        else:
            self.mitigation_nx = MitNX.NO 

    def _check_fortify(self):
        self.mitigation_fortify = MitFortify.NO
        if self.imports == None:
            return

        for imprt in self.imports:
            if imprt.startswith("_chk"):
                self.mitigation_fortify = MitFortify.YES


    def _check_excepttable(self):
        self.excepttable = '.gcc_except_table' in self.section_names

    def _heuristic_ehframe(self):
        self.behframe = self.__dwarf__.eh_frame_sec != None

    def _heuristic_vtables(self):
        vtables = []

        for section in self.symbol_tables:
            for symbol in section.iter_symbols():
                if (symbol['st_info']['type'] == "STT_OBJECT"
                        and symbol.name.startswith("_ZTV")):
                    # we have found a vtable
                    vtables = symbol.name

        self.vtable_symbols = vtables
        if len(vtables) > 0:
            return True

        return False

    def _heuristic_compiler(self):
        
        self.compiler = Compiler.UNKNOWN
        self.compilerinfo = 'Unknown'
        if self.comments == None:
            return

        for commentline in self.comments:
            if 'clang' in commentline:
                self.compiler = Compiler.CLANG
                self.compilerinfo = commentline
                break
            if 'Intel' in commentline:
                self.compiler = Compiler.ICC
                self.compilerinfo = commentline
            if 'GHC' in commentline:
                self.compiler = Compiler.GHC
                self.compilerinfo = commentline
                break
            if 'GNAT' in commentline:
                self.compiler = Compiler.GNAT
                self.compilerinfo = commentline
                break
           
            if 'GCC' in commentline:
                self.compiler = Compiler.GCC
                self.compilerinfo = commentline

    def _heuristic_language(self):
        
        if '.go.buildinfo' in self.section_names:
            self.language = Language.GO
            self.compiler = Compiler.GO
            return

        if self.compiler == Compiler.GNAT:
            self.language = Language.ADA
            return

        if self.compiler == Compiler.GHC:
            self.language = Language.HASKELL
            return

        if self.bsymbols:

            if 'rust_panic' in self.symbols:
                self.language = Language.RUST
                self.compiler = Compiler.RUSTC

            if '__cxx_global_var_init' in self.symbols:
                self.language = Language.CXX
                return

            if self.behframe and self._heuristic_vtables():
                self.language = Language.CXX
                return

    @classmethod
    def libs_to_links(cls, libs):
        lflags = []
        for lib in libs:
            lflag = "-l%s" % lib[3:].split(".so")[0]
            lflags.append(lflag)
        return lflags

    def report_json(self):

        reportobj = {
            'FILE': os.path.basename(self.path),
            'Entry Point': hex(self.entrypoint),
            'Linking': ("dynamic" if self.linktype == LinkType.DYNAMIC else "static"),
            'Interpreter': self.interpreter,
            'Symbols': ("yes" if self.bsymbols else "no"),
            'PIE': ("yes" if self.mitigation_pie == MitPIE.PIE else "no"),
            'RELRO': (RelRo[self.mitigation_relro]),
            'NX': ("yes" if self.mitigation_nx == MitNX.YES else "no"),
            'FORTIFY_SOURCE': ("yes" if self.mitigation_fortify else "no"),
            'Compiler': (CompilerFamily[self.compiler]),
            'Compiler Info': (self.compilerinfo),
            'Language': (LanguageNames[self.language]),
            'EH Frame': "yes" if self.behframe else "no",
            'gcc_except_table': "yes" if self.excepttable else "no",
            'VTables': "yes" if len(self.vtable_symbols) > 0 else "no",
            'LIBS': self.libs,
            'LFLAGS': self.lflags,
            'MD5' : self.md5,
            'SHA1' : self.sha1,
            'SHA256': self.sha256,
            'SHA3-256': self.sha3_256,
        }
        return reportobj

    def report(self):
        ro = self.report_json()
        for k,v in ro.items():
            print("%s: %s" % (k,v))

def __helper_report(file):
    fname = file
    with open(fname, 'rb') as f:
        e = ELFObject(f)
        e.checks()
        e.report()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Check ELF File for various characteristics")
    parser.add_argument('-f', '--file', required=True, help="File to analyse")
    
    args = parser.parse_args()

    fname = args.file
    with open(fname, 'rb') as f:
        e = ELFObject(f, path=fname)
        e.checks()
        e.report()
        reportobj = e.report_json()
        print(json.dumps(e.report_json()))
