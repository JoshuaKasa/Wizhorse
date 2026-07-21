/*
  Wizhorse starter YARA rule.
  Source: original rule for this plugin, using common public packer markers
  such as UPX section names and packer-related strings.
  License: MIT, same intended distribution terms as the Wizhorse plugin.
*/

rule Generic_Packer_Markers
{
    meta:
        description = "Detects common packer section/string markers in PE files"
        source = "Wizhorse original starter rule based on public packer markers"
        license = "MIT"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_sig = "UPX!" ascii
        $aspack = "ASPack" ascii nocase
        $mpress = "MPRESS" ascii nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}
