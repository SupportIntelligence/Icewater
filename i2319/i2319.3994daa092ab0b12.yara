
rule i2319_3994daa092ab0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.3994daa092ab0b12"
     cluster="i2319.3994daa092ab0b12"
     cluster_size="94"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem multiplug browsermodifier"
     md5_hashes="['e56a8f560018dcf4d0f74f9a5a1f96be527daf42','95524033f701c6fbdf9afa052f4b2d452759dcd7','3376cf36fc85a32ad4ca70bae04e964a8f033853']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.3994daa092ab0b12"

   strings:
      $hex_string = { 6577555249285f5f5343524950545f5552495f535045435f5f2c206e756c6c2c206e756c6c29293b0a20206f2e53657276696365732e7363726970746c6f6164 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
