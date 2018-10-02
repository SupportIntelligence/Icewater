
rule k2319_293d1ce9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.293d1ce9c8800b12"
     cluster="k2319.293d1ce9c8800b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['7d815784ecb0d840b2eb0584eaf3f2ea511a390e','291eb1c6ed92af27cef2c9366bcb7747797ffe3c','2a7bb7d5a65a585701b38742a1a4d799241339dd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.293d1ce9c8800b12"

   strings:
      $hex_string = { 2e293e30783232373f2245223a2830783132332c312e3431364533292929627265616b7d3b766172204639583d7b276238273a66756e6374696f6e28582c5938 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
