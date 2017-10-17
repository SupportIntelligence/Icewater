import "hash"

rule o3e9_04548104ca424e4a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.04548104ca424e4a"
     cluster="o3e9.04548104ca424e4a"
     cluster_size="55 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster malicious agngl"
     md5_hashes="['78dadb21c063cc4da60bc8a9dcf942a8', 'c433fbe5e64da5b2d5ab91672c31bf01', 'ab30477aa74e9fb0429b3168085853bf']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(334149,1025) == "6a1133e0f9f4205eea49f334d3e39860"
}

