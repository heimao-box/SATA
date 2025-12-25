/*
    加壳程序检测规则
    用于检测各种常见的加壳工具和混淆技术
*/

rule UPX_Packer
{
    meta:
        description = "检测UPX加壳程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "packer"

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "$Info: This file is packed with the UPX executable packer" ascii
        $upx3 = "UPX is Copyright" ascii
        $upx4 = { 55 50 58 21 }

    condition:
        any of ($upx*)
}

rule VMProtect_Packer
{
    meta:
        description = "检测VMProtect加壳程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "packer"

    strings:
        $vmp1 = ".vmp0" ascii
        $vmp2 = ".vmp1" ascii
        $vmp3 = ".vmp2" ascii
        $vmp4 = "VMProtect" ascii
        $vmp5 = { 68 ?? ?? ?? ?? C3 }

    condition:
        any of ($vmp*)
}

rule Themida_Packer
{
    meta:
        description = "检测Themida/WinLicense加壳程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "packer"

    strings:
        $themida1 = ".themida" ascii
        $themida2 = "Themida" ascii
        $themida3 = "WinLicense" ascii
        $themida4 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 }

    condition:
        any of ($themida*)
}

rule ASPack_Packer
{
    meta:
        description = "检测ASPack加壳程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "packer"

    strings:
        $aspack1 = ".aspack" ascii
        $aspack2 = ".adata" ascii
        $aspack3 = "ASPack" ascii
        $aspack4 = { 60 E8 ?? ?? ?? ?? 5D 81 ED }

    condition:
        any of ($aspack*)
}

rule PECompact_Packer
{
    meta:
        description = "检测PECompact加壳程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "packer"

    strings:
        $pec1 = "PECompact2" ascii
        $pec2 = ".pec1" ascii
        $pec3 = ".pec2" ascii
        $pec4 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 }

    condition:
        any of ($pec*)
}

rule FSG_Packer
{
    meta:
        description = "检测FSG加壳程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "packer"

    strings:
        $fsg1 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 }
        $fsg2 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? }
        $fsg3 = { EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00 }

    condition:
        any of ($fsg*)
}

rule MPRESS_Packer
{
    meta:
        description = "检测MPRESS加壳程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "packer"

    strings:
        $mpress1 = ".MPRESS1" ascii
        $mpress2 = ".MPRESS2" ascii
        $mpress3 = "MPRESS" ascii
        $mpress4 = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 }

    condition:
        any of ($mpress*)
}

rule Armadillo_Packer
{
    meta:
        description = "检测Armadillo加壳程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "packer"

    strings:
        $arm1 = "Armadillo" ascii
        $arm2 = ".data" ascii
        $arm3 = ".rdata" ascii
        $arm4 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? }

    condition:
        any of ($arm*)
}

rule Obsidium_Packer
{
    meta:
        description = "检测Obsidium加壳程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "packer"

    strings:
        $obs1 = ".obsidium" ascii
        $obs2 = "Obsidium" ascii
        $obs3 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? }

    condition:
        any of ($obs*)
}

rule PESpin_Packer
{
    meta:
        description = "检测PESpin加壳程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "packer"

    strings:
        $pespin1 = ".pespin" ascii
        $pespin2 = "PESpin" ascii
        $pespin3 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 }

    condition:
        any of ($pespin*)
}

rule Generic_Packer_Indicators
{
    meta:
        description = "检测通用加壳特征"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "low"
        category = "packer"

    strings:
        $pack1 = "packed" ascii nocase
        $pack2 = "compressed" ascii nocase
        $pack3 = "encrypted" ascii nocase
        $pack4 = "obfuscated" ascii nocase
        $pack5 = "protector" ascii nocase
        $pack6 = "crypter" ascii nocase

    condition:
        any of ($pack*)
}

rule High_Entropy_Sections
{
    meta:
        description = "检测高熵值段（可能的加密/压缩数据）"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "low"
        category = "entropy"

    condition:
        // 这个规则需要在实际实现中通过计算段的熵值来判断
        // 这里只是一个占位符，实际使用时需要配合熵值计算
        false
}

rule Suspicious_Section_Names
{
    meta:
        description = "检测可疑的段名称"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "sections"

    strings:
        $sec1 = ".packed" ascii
        $sec2 = ".crypted" ascii
        $sec3 = ".compressed" ascii
        $sec4 = ".encoded" ascii
        $sec5 = ".protected" ascii
        $sec6 = ".obfus" ascii
        $sec7 = ".vmp" ascii
        $sec8 = ".upx" ascii

    condition:
        any of ($sec*)
}

rule Anti_Disassembly
{
    meta:
        description = "检测反汇编对抗技术"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "anti_analysis"

    strings:
        $anti1 = { E8 00 00 00 00 }  // call $+5
        $anti2 = { EB 00 }           // jmp $+2
        $anti3 = { E9 00 00 00 00 }  // jmp $+5
        $anti4 = { 74 01 }           // jz $+1
        $anti5 = { 75 01 }           // jnz $+1

    condition:
        2 of ($anti*)
}

rule Code_Caves
{
    meta:
        description = "检测代码洞穴技术"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "injection"

    strings:
        $cave1 = { 00 00 00 00 00 00 00 00 00 00 E9 }
        $cave2 = { CC CC CC CC CC CC CC CC CC CC E8 }
        $cave3 = { 90 90 90 90 90 90 90 90 90 90 }

    condition:
        any of ($cave*)
}