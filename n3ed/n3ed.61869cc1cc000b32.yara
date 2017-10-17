import "hash"

rule n3ed_61869cc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.61869cc1cc000b32"
     cluster="n3ed.61869cc1cc000b32"
     cluster_size="55 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['ba1b6cac14524dc933a080a8affab95d', '9adfb861c5b249d554e624a81666cc6f', 'baf9405d8b30fd63442f11584093e871']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(167936,1024) == "144e96e91446d4ce95cb3c26d5e672a6"
}

