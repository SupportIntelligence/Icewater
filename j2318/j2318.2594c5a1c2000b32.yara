
rule j2318_2594c5a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2318.2594c5a1c2000b32"
     cluster="j2318.2594c5a1c2000b32"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector eiframeinjectadswarenme html"
     md5_hashes="['b072d66e503ec44937002df10de4edcfc94e89d0','38afdc8f6672dc5d211ff423087529da611bccda','5e0d12b1efe6e995ddb76d9bab800e067974a52a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2318.2594c5a1c2000b32"

   strings:
      $hex_string = { 3d227864526e6535595a516f336a6f4d49737a7156792d6e506974352d766d50315950414d6e62723765566d4122202f3e0d0a3c212d2d3c6d65746120636861 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
