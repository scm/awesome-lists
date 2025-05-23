rule TrojanSpy_AndroidOS_SMisor_A_2147822183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMisor.A!MTB"
        threat_id = "2147822183"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMisor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 00 e8 03 71 20 ?? ?? 10 00 22 00 ?? ?? 70 10 ?? ?? 00 00 22 01 ?? ?? 70 10 ?? ?? 01 00 22 02 ?? ?? 70 10 ?? ?? 02 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 54 53 ?? ?? 6e 20 ?? ?? 32 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 54 53 ?? ?? 6e 20 ?? ?? 32 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 54 53 ?? ?? 6e 20 ?? ?? 32 00 6e 10 ?? ?? 02 00 0c 02 6e 20 ?? ?? 21 00 0c 01 6e 10 ?? ?? 01 00 0c 01}  //weight: 1, accuracy: Low
        $x_1_2 = {16 00 e8 03 71 20 ?? ?? 10 00 22 00 ?? ?? 70 10 ?? ?? 00 00 22 01 ?? ?? 70 10 ?? ?? 01 00 22 02 ?? ?? 70 10 ?? ?? 02 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 54 63 ?? ?? 6e 20 ?? ?? 32 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 54 63 ?? ?? 6e 20 ?? ?? 32 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 54 63 ?? ?? 54 64 ?? ?? 71 20 ?? ?? 43 00 0c 03 6e 20 ?? ?? 32 00 6e 10 ?? ?? 02 00 0c 02 6e 20 ?? ?? 21 00 0c 01 6e 10 ?? ?? 01 00 0c 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

