
rule o26c0_491eea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.491eea48c0000b12"
     cluster="o26c0.491eea48c0000b12"
     cluster_size="138"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious genericrxer heuristic"
     md5_hashes="['7b31ba612f75d1c844edcbf00eea85600e2c8995','b845bbb499e65fed0496317ef57b491abdd4fb66','39e709e34748040c10738ef67e0c4e48d6882f5c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.491eea48c0000b12"

   strings:
      $hex_string = { f940731580f92073060fa5c2d3e0c38bd033c080e11fd3e2c333c033d2c3cc833d544b4100007437558bec83ec0883e4f8dd1c24f20f2c0424c9c3833d544b41 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
