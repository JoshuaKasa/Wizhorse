/*
  Wizhorse starter YARA rule.
  Source: original rule for this plugin, using the public YARA PE module API.
  License: MIT, same intended distribution terms as the Wizhorse plugin.
*/

import "pe"

rule PE_Anomalous_Section_Count
{
    meta:
        description = "Flags PE files with an unusual section count"
        source = "Wizhorse original starter rule using YARA PE module fields"
        license = "MIT"
    condition:
        uint16(0) == 0x5A4D and (pe.number_of_sections == 0 or pe.number_of_sections > 16)
}
