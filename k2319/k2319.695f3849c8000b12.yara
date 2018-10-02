
rule k2319_695f3849c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.695f3849c8000b12"
     cluster="k2319.695f3849c8000b12"
     cluster_size="50"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem script browext"
     md5_hashes="['45cbc9b1579b81804a5d290e16a08608d2f8e337','7aab643151ebfafeab954d0b65a5ea095fc09d5f','c8cc058da54b35bd8a7a35cf81d99359ffa24345']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.695f3849c8000b12"

   strings:
      $hex_string = { 44354b2e7033492b483444354b2e773749292c6465636f64653a66756e6374696f6e28672c6a297b766172206e3d226638222c623d2838362e3745313c283132 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
