import "hash"

rule SH_injection_mock_pe_exe_34c87be9
{
  meta:
    author = "SymbolicHunter"
    date = "2025-10-16"
    description = "Auto-generated from analysis of injection_mock_pe.exe"
    sha256 = "34c87be9d0e15a4a09f58915a03915e4fe3a6811cd949eaf340db74f4194f5df"
    md5 = "391f21e02d6b0f607d651758e4d2dc57"
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
    (hash.sha256(0, filesize) == "34c87be9d0e15a4a09f58915a03915e4fe3a6811cd949eaf340db74f4194f5df") or
    (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACE or uint32(0) == 0xCEFAEDFE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xCAFEBABE and any of ($s*))
}
