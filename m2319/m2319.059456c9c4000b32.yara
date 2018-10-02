
rule m2319_059456c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.059456c9c4000b32"
     cluster="m2319.059456c9c4000b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe script dzfjls"
     md5_hashes="['a863b2e3224600debe5ec4be3847f6bea289c293','24d9a15c0d32a8f024f5ffdecdfc452bedeadf21','ecaf20d6dfaae0b7e1a9db3f683688d5e8a90186']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.059456c9c4000b32"

   strings:
      $hex_string = { 3e3c215b43444154415b2f2f3e3c212d2d0d0a5f6a61536b696e203d202250686f746f426f78223b0d0a5f6a615374796c65203d20224461726b2e637373223b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
