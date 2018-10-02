
rule k2319_29129ee9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29129ee9c8800b32"
     cluster="k2319.29129ee9c8800b32"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['bcc38c5902f14269e92a82b64578a1b4b63ca6a5','03659f1a64491b452a9f79b725e8cfe0930f3475','b3465f796d7343f461117f6350c984b351de08bd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29129ee9c8800b32"

   strings:
      $hex_string = { 2830783231422c322e38314532292929627265616b7d3b766172207334473d7b27693534273a362c27613634273a2249222c2751273a66756e6374696f6e2847 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
