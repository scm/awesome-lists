rule Trojan_Win64_Alevaul_DA_2147943959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alevaul.DA!MTB"
        threat_id = "2147943959"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alevaul"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 0b b8 1f 85 eb 51 f7 e9 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 19 2b c8 80 c1 41 88 0b 48 ff c3 49 ff c9}  //weight: 10, accuracy: High
        $x_10_2 = {44 89 4c 24 60 44 89 54 24 64 48 8b ce 49 8b c0 48 f7 e1 48 8b c1 48 ff c1 48 c1 ea 02 48 6b d2 0d 48 2b c2 8a 44 05 88 30 44 0c 5f 48 83 f9 13}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Alevaul_DB_2147943960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alevaul.DB!MTB"
        threat_id = "2147943960"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alevaul"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 f8 42 0f b6 54 17 08 8d 04 16 0f b6 f0 42 8a 44 16 08 42 88 44 17 08 42 88 54 16 08 42 0f b6 4c 17 08 03 ca 81 e1 ff 00 00 80}  //weight: 10, accuracy: High
        $x_10_2 = {41 0f b6 c9 44 88 4c 04 38 8b c2 0f b6 44 04 38 03 c1 25 ff 00 00 80}  //weight: 10, accuracy: High
        $x_10_3 = {0f b6 d8 41 0f b6 14 18 8d 04 17 0f b6 f8 0f b6 04 39 41 88 04 18 88 14 39 41 0f b6 04 18 03 c2 25 ff 00 00 80}  //weight: 10, accuracy: High
        $x_5_4 = {48 63 c1 42 8a 4c 10 08 42 32 0c 1b 41 88 0b 49 ff c3 49 ff c9}  //weight: 5, accuracy: High
        $x_5_5 = {48 63 c8 49 ff c3 0f b6 44 0c 38 41 32 43 ff 48 ff c3 88 43 ff c7 84 24 50 01 00 00 98 b4 01 00}  //weight: 5, accuracy: High
        $x_5_6 = {48 63 c8 49 ff c1 0f b6 44 0c 18 43 32 44 0b ff 41 88 41 ff 49 ff ca}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Alevaul_GDI_2147943982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alevaul.GDI!MTB"
        threat_id = "2147943982"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alevaul"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {42 99 5c 69 a4 f2 ?? ?? ?? ?? 37 7b 00 22 58 00 b2}  //weight: 5, accuracy: Low
        $x_5_2 = {48 8d 5c 24 ?? 49 83 f8 10 48 0f 43 5c 24 ?? 48 ff c1 e8 ?? ?? ?? ?? 4c 8b d8 48 8b d0 48 2b d3 0f b6 0b 88 0c 1a 48 8d 5b ?? 84 c9 ?? ?? 44 8b d7 41 0f b7 5f ?? 48 85 db}  //weight: 5, accuracy: Low
        $x_10_3 = {49 03 f9 49 03 d1 3b c0 75 30 33 c9 8a 1a 84 db ?? ?? d1 c1 69 c1 f2 6d 00 00 80 fb 61 0f b6 cb 89 44 24 20 8d 43 e0 0f b6 c0 0f 43 c8 30 4c 24 20 8b 4c 24 20 48 ff c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

