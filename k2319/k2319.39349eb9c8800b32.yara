
rule k2319_39349eb9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39349eb9c8800b32"
     cluster="k2319.39349eb9c8800b32"
     cluster_size="43"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5af80b493bb49d06e6acd839d0cc5b1daa412163','ccd35e153c16120e053fd531ad1ee93492defe37','6ac54f839a8d1b8979b81db6abcc1ac1c82375da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39349eb9c8800b32"

   strings:
      $hex_string = { 6566696e6564297b72657475726e204c5b6b5d3b7d76617220573d2828307834412c39293e2830783134322c3837293f22474554223a2832362c3131382e293c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
