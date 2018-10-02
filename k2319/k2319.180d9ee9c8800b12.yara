
rule k2319_180d9ee9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.180d9ee9c8800b12"
     cluster="k2319.180d9ee9c8800b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['fc964bf22993e4aaf8b49353b71d6be18a13a8ca','e92ba414325cd3d5ff5d4b6ecb88434d8ebe9631','61472143e6aec2b26de9add9ca05f0d421a40631']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.180d9ee9c8800b12"

   strings:
      $hex_string = { 2e353945323f28312e30373645332c313139293a2832312c3930292929627265616b7d3b7661722073325a31593d7b27493559273a66756e6374696f6e284a2c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
