
rule m2319_199e56c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.199e56c9c8000b32"
     cluster="m2319.199e56c9c8000b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker likejack clicker"
     md5_hashes="['345234b78ba192241599a8bb5315649980f69d1e','b628677b6f11934331856c9939be61645d0eb0eb','02d90a7b628d2fc70a9e92de88a8995d3db14167']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.199e56c9c8000b32"

   strings:
      $hex_string = { 747970653d22636f6c6f72222064656661756c743d2223343434343434222f3e0a3c5661726961626c65206e616d653d227769646765742e6c696e6b2e686f76 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
