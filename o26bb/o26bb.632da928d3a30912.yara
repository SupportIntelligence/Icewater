
rule o26bb_632da928d3a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.632da928d3a30912"
     cluster="o26bb.632da928d3a30912"
     cluster_size="35"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['387f5345f50c5cbdbef137a49530e783e5cecd1d','faabfcd344cb3cb98b3b0a84752c3c3d182be034','be066ac496d8d3fe59c7a5bb36f7c3458f7e6bb6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.632da928d3a30912"

   strings:
      $hex_string = { 111100161616001c1c1c002222220029292900555555004d4d4d004242420039393900ff7c8000ff505000d6009300ccecff00efd6c600e7e7d600ada9900033 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
