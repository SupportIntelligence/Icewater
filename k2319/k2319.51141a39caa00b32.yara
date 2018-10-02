
rule k2319_51141a39caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.51141a39caa00b32"
     cluster="k2319.51141a39caa00b32"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e18be4e542f634fcc4b0825003325311a842e86b','6901d85020185db46e18a6a15059454a2140befd','d2979ac139c8b504007e1e215b5c28bd64165e88']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.51141a39caa00b32"

   strings:
      $hex_string = { 6566696e6564297b72657475726e204a5b545d3b7d76617220423d2839363c2830783144382c30783841293f28307834332c30786363396532643531293a2834 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
