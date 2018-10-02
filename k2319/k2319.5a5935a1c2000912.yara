
rule k2319_5a5935a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a5935a1c2000912"
     cluster="k2319.5a5935a1c2000912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['7f94ca0b8cf9f71d778f8f103722aedf597cf527','39678e17c8bad02e63f89f38b80b59cb9149e9f9','29092d78b41f49f8969c47af55e03733ce495050']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a5935a1c2000912"

   strings:
      $hex_string = { 646f773b666f72287661722045314820696e207634443148297b6966284531482e6c656e6774683d3d3d2830783235363e3d2830783136422c3433293f283932 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
