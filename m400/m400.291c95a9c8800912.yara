import "hash"

rule m400_291c95a9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m400.291c95a9c8800912"
     cluster="m400.291c95a9c8800912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sality malicious sector"
     md5_hashes="['4505634aea7823e7f330b7f6a4583166', '8c348aa5a1cbff521c295df14041e391', '4505634aea7823e7f330b7f6a4583166']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(14336,1024) == "9e6cead361e0acd9a574017736bb5643"
}

