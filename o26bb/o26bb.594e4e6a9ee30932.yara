
rule o26bb_594e4e6a9ee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594e4e6a9ee30932"
     cluster="o26bb.594e4e6a9ee30932"
     cluster_size="225"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious btlfk"
     md5_hashes="['69120c7ecb938bfb57c41fbd92640cbfbf5546da','fb0b9870b424c14698ad4715278c4461f1be9f47','89e504f53bc0af1f28b07896ac9d718eb29e9523']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594e4e6a9ee30932"

   strings:
      $hex_string = { cb880842400fb6c992e809d0ffff5bc38d4000558bec565789c68b7d0831c00a06742b85d27e1839c27f1b29d04085c97c1439c17f1401d6880f47f3a4eb11ba }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
