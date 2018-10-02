
rule k2319_392c9ca9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.392c9ca9c8800932"
     cluster="k2319.392c9ca9c8800932"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a016fdabcfd0c4cb52a034af755ebbf245e68356','7b7a6831f88b63dc935f69993cca22ecc026aa72','fb7ec4e269283381ddfe612f3957d0414eb4bf93']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.392c9ca9c8800932"

   strings:
      $hex_string = { 775b575d213d3d756e646566696e6564297b72657475726e20775b575d3b7d766172204f3d28307844413c2835322e2c37342e394531293f283134382e323045 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
