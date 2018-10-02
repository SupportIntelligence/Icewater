
rule k2319_29169699c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29169699c2200b32"
     cluster="k2319.29169699c2200b32"
     cluster_size="67"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4ca77a5ecf7cd61a52bd74341ae50f9154a643c7','663a261b12464b50909a214adb91d2a86aab017e','821d16f8e80fd25631aceea900d5561d9a519236']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29169699c2200b32"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e206e5b725d3b7d76617220493d2828307838332c352e354532293c32382e3645313f2834342c226a22293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
