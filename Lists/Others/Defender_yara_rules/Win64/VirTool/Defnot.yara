rule VirTool_Win64_Defnot_A_2147941249_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Defnot.A"
        threat_id = "2147941249"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Defnot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8b cb ff ?? ?? ?? ?? ?? 48 8b c8 48 89 07 48 83 f8 ff 0f 95 c0 88 47 08 ?? ?? 48 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 8b d3 ff}  //weight: 10, accuracy: Low
        $x_10_2 = {10 e4 00 4f 08 00 80 92 e9 03 80 52 e9 01 a0 72 01 00 80 52 ?? 42 00 ad 6a 02 40 39 88 02 00 f9 48 00 80 52 9f 22 00 39 9f 0a 00 f9 5f 09 00 71 8a 62 00 39 29 01 88 1a 9f 66 00 39 5f 01 00 71 88 00 80 52 13 01 89 1a ?? ?? ?? ?? 02 ?? ?? ?? e8 ?? ?? ?? 08 ?? ?? ?? e0 03 13 2a 00 01 3f d6 1f 04 00 b1 80 02 00 f9 e8 07 9f 1a 88 22 00 39 1f 04 00 b1 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_1_3 = "defender-disabler-ipc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

