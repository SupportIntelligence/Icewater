import "hash"

rule m400_2b1c95a9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m400.2b1c95a9c8800b32"
     cluster="m400.2b1c95a9c8800b32"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sality malicious sector"
     md5_hashes="['fc32f09328db0b11598dd4012b58713f', '4b287f207171c291c9051896a4d6576b', '6776f18d7de5f3cc03b01ba9826a2f06']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(14336,1024) == "9e6cead361e0acd9a574017736bb5643"
}

