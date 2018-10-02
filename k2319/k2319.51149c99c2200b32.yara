
rule k2319_51149c99c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.51149c99c2200b32"
     cluster="k2319.51149c99c2200b32"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['dfc20bde37c0466e582052a9e607b06b4bd27cbd','b26cd25b7eb7de0061dca75a55e2dec2b8329b26','9258351a24665cc7b48d16b2587b16f3618ec60d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.51149c99c2200b32"

   strings:
      $hex_string = { 6566696e6564297b72657475726e204a5b545d3b7d76617220423d2839363c2830783144382c30783841293f28307834332c30786363396532643531293a2834 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
