
rule j2318_21b439a9c8801932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2318.21b439a9c8801932"
     cluster="j2318.21b439a9c8801932"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector eiframeinjectadswarenme html"
     md5_hashes="['1fe83e814482f4f8b4c34e8f7098b70533bab4a3','bbe29abd16293ca713b6b3e38c70ff9133178a5d','d5ddf919b4c2931400c2ef16abefaa0a86bd4b40']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2318.21b439a9c8801932"

   strings:
      $hex_string = { 3d227864526e6535595a516f336a6f4d49737a7156792d6e506974352d766d50315950414d6e62723765566d4122202f3e0d0a3c212d2d3c6d65746120636861 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
