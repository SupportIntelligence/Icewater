
rule i2319_1a9b3949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.1a9b3949c8000b12"
     cluster="i2319.1a9b3949c8000b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="exploit cmpztx expkit"
     md5_hashes="['1a270f51ec1cbe4d3e6dac031771e947de4e6002','c5c4f4f7a20f8d4f2479a5431981442720d24ba3','7118bd14ce6a8c0fcb510f3f08455148f93b6b14']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.1a9b3949c8000b12"

   strings:
      $hex_string = { 20537472696e67223b4f6c6c6c4f4f3d2274696f6e223b4f6c4f6c6c4f3d22436f64652878297d223b4f6c6c4f4f4f3d2243686172223b4f6c6c6c4f6c3d2266 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
