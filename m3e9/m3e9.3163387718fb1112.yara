import "hash"

rule m3e9_3163387718fb1112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163387718fb1112"
     cluster="m3e9.3163387718fb1112"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qvod viking jadtre"
     md5_hashes="['56373762aed982b26a1b82d592f5a127', '6c6294c76d5a5cdfc12ef566ff1462c9', 'd55f192f91b0ecee8fb6123b1c6f0b30']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64512,1024) == "85f1932459668fd27cfde94d6b3d6030"
}

