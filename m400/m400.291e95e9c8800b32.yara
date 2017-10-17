import "hash"

rule m400_291e95e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m400.291e95e9c8800b32"
     cluster="m400.291e95e9c8800b32"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sality malicious sector"
     md5_hashes="['acd95140dfe30f2a1c9f70b1623dafb7', 'acd95140dfe30f2a1c9f70b1623dafb7', '83560e7aef7ba7d9eabb1c1c62f063d9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(14336,1024) == "9e6cead361e0acd9a574017736bb5643"
}

