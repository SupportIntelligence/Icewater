import "hash"

rule o3e9_16532862ded24b9e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.16532862ded24b9e"
     cluster="o3e9.16532862ded24b9e"
     cluster_size="337 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['d28326380eea866130bfc026d0b73d32', '264c1bf17ae1b4c7774978370a39480a', '53453a2df9038f24573cfd69abc31e08']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(50224,1025) == "f47d5c6b9aa39903e8d5cb14a831cbf6"
}

