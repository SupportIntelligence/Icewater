
rule j2318_2690c5a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2318.2690c5a1c2000b32"
     cluster="j2318.2690c5a1c2000b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector eiframeinjectadswarenme html"
     md5_hashes="['fd15be145cee5e18d4c139c6bb4a8fdd748121ea','fcbf2df67b58abf7dc1bba1462c8e3ea5b09beb8','b251c12521dd420d7c3bbb27de51c09e6ca19bb2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2318.2690c5a1c2000b32"

   strings:
      $hex_string = { 3d227864526e6535595a516f336a6f4d49737a7156792d6e506974352d766d50315950414d6e62723765566d4122202f3e0d0a3c212d2d3c6d65746120636861 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
