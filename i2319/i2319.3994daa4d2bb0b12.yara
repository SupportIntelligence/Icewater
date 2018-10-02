
rule i2319_3994daa4d2bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.3994daa4d2bb0b12"
     cluster="i2319.3994daa4d2bb0b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="megasearchplugin multiplug diplugem"
     md5_hashes="['fbbb9162309a6366c6aa420844536b79165b6093','a6c0ac205a687f078027ffc756de69bbd28cbd93','f06bbc6e7e1ffce81fb2e0279fe0a0c9486b378a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.3994daa4d2bb0b12"

   strings:
      $hex_string = { 6577555249285f5f5343524950545f5552495f535045435f5f2c206e756c6c2c206e756c6c29293b0a20206f2e53657276696365732e7363726970746c6f6164 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
