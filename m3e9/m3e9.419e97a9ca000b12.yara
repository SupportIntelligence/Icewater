import "hash"

rule m3e9_419e97a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.419e97a9ca000b12"
     cluster="m3e9.419e97a9ca000b12"
     cluster_size="36 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack starman"
     md5_hashes="['a86aa9080d5be8033a3a4c8b8d12e0a6', 'ddc5c722aa390598e2d3d2247aeb0976', 'ddc5c722aa390598e2d3d2247aeb0976']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(73291,1029) == "da5ab260d3f3b2aa7508f7dfc1ddb857"
}

