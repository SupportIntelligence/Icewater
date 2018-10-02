
rule o2319_4b9d6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.4b9d6a49c0000b12"
     cluster="o2319.4b9d6a49c0000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['b77b9c618f969b4debd4828f7b1c2a45a59d2158','71882d56799256002de0f34b3b1a1ac059b9a82f','f82bff855535e111ac95c20bb117193414f50294']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.4b9d6a49c0000b12"

   strings:
      $hex_string = { 74696f6e2861297b72657475726e20613f612e7265706c616365282f5b21222425262728292a2b2c2e5c2f3a3b3c3d3e3f405c5b5c5d5c5e607b7c7d7e5d2f67 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
