
rule o26bb_632da1a4dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.632da1a4dda30912"
     cluster="o26bb.632da1a4dda30912"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['01fd64133de21327dfc710de571a1514e1f61cdf','8d6eecce909f77b394531d3faa1f3cd96ea9809d','a569141b98afa46bbc26e639ecb45de09c44dc06']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.632da1a4dda30912"

   strings:
      $hex_string = { 33315b4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a5d000000253032643a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
