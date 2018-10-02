
rule k2319_6904c1cbc2220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6904c1cbc2220932"
     cluster="k2319.6904c1cbc2220932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik script"
     md5_hashes="['c5d2ebc0db5debfef6e74ce3faa3919642743064','d95694b71355f3e7a7098d178805755b25fc2d55','bfb66a844d3a927ad7986f9f6ae80a93da9a823e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6904c1cbc2220932"

   strings:
      $hex_string = { 283134372c30783236292929627265616b7d3b766172206d3668394e3d7b274c3362273a2261222c276b384e273a66756e6374696f6e286e2c41297b72657475 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
