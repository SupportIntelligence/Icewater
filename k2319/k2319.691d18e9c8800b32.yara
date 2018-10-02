
rule k2319_691d18e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.691d18e9c8800b32"
     cluster="k2319.691d18e9c8800b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e8db828b7ee410c3de422cd5328fac51262e17a9','2d8f2f00432b8a17f88d4a8ad8ba364015e5f46e','fa0dedb3ba4b542ec6d895bfb0a37021a5a10da5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.691d18e9c8800b32"

   strings:
      $hex_string = { 39293a28312e30363145332c38342e292929627265616b7d3b76617220423444375a3d7b2747356d273a2275222c2765375a273a66756e6374696f6e28522c59 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
