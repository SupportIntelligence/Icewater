import "hash"

rule n3ed_618746c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.618746c9c4000b32"
     cluster="n3ed.618746c9c4000b32"
     cluster_size="37 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['512103eba2616ce78da44c2e1d57345b', '7dfce5fccd9290d4603143b12502fd9e', '347e3a8aeee6f63ee10cc1686eb07abf']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(156672,1536) == "0f4c07f5fc878e2aa1805fefc0c25f7a"
}

