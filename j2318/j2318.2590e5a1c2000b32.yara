
rule j2318_2590e5a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2318.2590e5a1c2000b32"
     cluster="j2318.2590e5a1c2000b32"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector html hdgv"
     md5_hashes="['0980ff7970409e45b947b46d57019a6987228107','c4c242b8ba229ad9276b4aaf6b92adfec1983322','5b8a4fb8012fd1967efd22d509766e652ead2f8f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2318.2590e5a1c2000b32"

   strings:
      $hex_string = { 3d227864526e6535595a516f336a6f4d49737a7156792d6e506974352d766d50315950414d6e62723765566d4122202f3e0d0a3c212d2d3c6d65746120636861 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
