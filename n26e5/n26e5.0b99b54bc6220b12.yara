
rule n26e5_0b99b54bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26e5.0b99b54bc6220b12"
     cluster="n26e5.0b99b54bc6220b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious risktool kryptik"
     md5_hashes="['1a55114445328e30312090bc88fbda72d8d0dcea','26f64c702c6a09e5d6eb98d0be614feb3826b956','b2a8ec666b52c86a51041c19d1b58bfb1b156375']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26e5.0b99b54bc6220b12"

   strings:
      $hex_string = { 95ddf898d9da8ebffa23a58674f41ee3d641a1183af0695f795b63d49eff8956bb912a555919cb0b88049c1f874b6ed227e8f780be0cfc14b65d244557c9058d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
