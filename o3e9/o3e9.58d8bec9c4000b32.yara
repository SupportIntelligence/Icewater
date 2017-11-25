
rule o3e9_58d8bec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.58d8bec9c4000b32"
     cluster="o3e9.58d8bec9c4000b32"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock krypt nabucur"
     md5_hashes="['215dc3003879d57fbcdeb4ff96f4e4df','778db56f99148ac873313d7ed2274758','f719517a533d0ba116220a613719c948']"

   strings:
      $hex_string = { f8d5b3fff5d3b2fff3d0b1fff0ceafffeecbaeffeccaacffebc8abffe8c5a9ffe5c2a8ffe3c0a6ffe2bfa5ffe0bda3ffddbaa2ffdab8a1ffdeae8fc6dfac8514 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
