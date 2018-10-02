
rule i2319_1a9911a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.1a9911a9c8000b12"
     cluster="i2319.1a9911a9c8000b12"
     cluster_size="219"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="exploit cmpztx lololo"
     md5_hashes="['9553a6956794cd4f042b1874195d5eff5e15f3c4','f0dd3abff9f5e12524dd9a03e52ce603f366400b','6a094b095849c358e1bbdd634c0b8f780cdc3eb1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.1a9911a9c8000b12"

   strings:
      $hex_string = { 20537472696e67223b4f6c6c6c4f4f3d2274696f6e223b4f6c4f6c6c4f3d22436f64652878297d223b4f6c6c4f4f4f3d2243686172223b4f6c6c6c4f6c3d2266 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
