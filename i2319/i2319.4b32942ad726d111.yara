
rule i2319_4b32942ad726d111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.4b32942ad726d111"
     cluster="i2319.4b32942ad726d111"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos expkit html"
     md5_hashes="['99f8fbcea7f36b3df8a44e9a19b1ace509fb4a8b','ccd191a5545ae31c9f9071f457b8cbc91f92cdba','175d8b45dd49a4364a71bd1d79f78465a0c7c798']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.4b32942ad726d111"

   strings:
      $hex_string = { 7472696e6728293b0d0a09090d0a2020202076617220615f616c6c5f636f6f6b696573203d20646f63756d656e742e636f6f6b69652e73706c69742820273b27 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
