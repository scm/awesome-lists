rule TrojanDownloader_MSIL_Lazy_RDF_2147890436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.RDF!MTB"
        threat_id = "2147890436"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 08 00 00 0a 6f 09 00 00 0a 6f 0a 00 00 0a 73 0b 00 00 0a 20 a2 10 40 05 6f 0c 00 00 0a 13 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Lazy_RP_2147915041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.RP!MTB"
        threat_id = "2147915041"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Users\\ALIENWARE\\Downloads\\Telegram Desktop\\ConsoleApp1\\ConsoleApp1\\obj\\Debug\\" ascii //weight: 10
        $x_1_2 = "del del.bat" wide //weight: 1
        $x_1_3 = "loader20" wide //weight: 1
        $x_1_4 = "U29mdHdhcmVJbnN0YWxsZXIq" wide //weight: 1
        $x_10_5 = "_Encrypted$" wide //weight: 10
        $x_1_6 = "SoftwareInstaller.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Lazy_NITA_2147921882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.NITA!MTB"
        threat_id = "2147921882"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 f9 01 00 70 0a 73 34 00 00 0a 0b 73 29 00 00 0a 25 72 e9 00 00 70 6f ?? 00 00 0a 00 25 72 a0 03 00 70 06 72 b6 03 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 16 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 72 65 00 00 70}  //weight: 2, accuracy: Low
        $x_2_2 = {73 12 00 00 06 0a 00 06 73 2e 00 00 0a 7d 0a 00 00 04 72 af 01 00 70 02 28 ?? 00 00 2b 06 fe 06 13 00 00 06 73 30 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 33 00 00 0a 0b 2b 00 07 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

