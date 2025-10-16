import "hash"

rule SH_injection_mock_pe_exe_4a17e675
{
  meta:
    author = "SymbolicHunter"
    date = "2025-10-15"
    description = "Auto-generated from analysis of injection_mock_pe.exe"
    sha256 = "4a17e675a6d0eeacff3f501fee8b52f9826c0b7476b91d6c9b8fa5d0024329d7"
    md5 = "b501eda927ba076a2f6b6b6fef3da6a1"
    source = "SymbolicHunter"

  strings:
    $s1 = "___mingw_GetSectionForAddress" nocase ascii
    $s2 = "___mingw_GetSectionCount" nocase ascii
    $s3 = "__FindPESectionExec" nocase ascii
    $s4 = "___mingw_printf" nocase ascii
    $s5 = "_calloc" nocase ascii
    $s6 = "_fprintf" nocase ascii
    $s7 = "_malloc" nocase ascii
    $s8 = "_vfprintf" nocase ascii
    $s9 = "GetProcAddress" nocase ascii
    $s10 = "LoadLibraryA" nocase ascii
    $s11 = "VirtualProtect" nocase ascii
    $s12 = "calloc" nocase ascii
  condition:
    (hash.sha256(0, filesize) == "4a17e675a6d0eeacff3f501fee8b52f9826c0b7476b91d6c9b8fa5d0024329d7") or
    (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xCAFEBABE and any of ($s*))
}
