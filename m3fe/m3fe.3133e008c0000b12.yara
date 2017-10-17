import "hash"

rule m3fe_3133e008c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3fe.3133e008c0000b12"
     cluster="m3fe.3133e008c0000b12"
     cluster_size="28 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="paph malicious backdoor"
     md5_hashes="['f6ea8310066a58bbceb4ca018d40c707', '16c34cd496e793d3de7f7692b14c0afd', '32c5dedeff77f6a947df0cd585ebfacc']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(21504,1024) == "0b80fa918bd71a51c45f5ec913e75f05"
}

