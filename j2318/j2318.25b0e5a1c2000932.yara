
rule j2318_25b0e5a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2318.25b0e5a1c2000932"
     cluster="j2318.25b0e5a1c2000932"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector eiframeinjectadswarenme html"
     md5_hashes="['c14de6e5f008e0d55c466c247cdc537cdfde2b49','29d73ac24a9f9cf8768b48e7bfd292bfae87c967','e79b069149a6058ca5872f9edc5b03879f8f112f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2318.25b0e5a1c2000932"

   strings:
      $hex_string = { 3d227864526e6535595a516f336a6f4d49737a7156792d6e506974352d766d50315950414d6e62723765566d4122202f3e0d0a3c212d2d3c6d65746120636861 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
