
rule i2319_1a9b15a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.1a9b15a9c8000b12"
     cluster="i2319.1a9b15a9c8000b12"
     cluster_size="296"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="exploit cmpztx lololo"
     md5_hashes="['848b9ce4a558d1f130d12e598d1d8eee58219d5c','a53749234736c9a34b1654c277973439326989e6','fa06273d80d432ab1a1c0b6389bf52e6ffae1ee2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.1a9b15a9c8000b12"

   strings:
      $hex_string = { 20537472696e67223b4f6c6c6c4f4f3d2274696f6e223b4f6c4f6c6c4f3d22436f64652878297d223b4f6c6c4f4f4f3d2243686172223b4f6c6c6c4f6c3d2266 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
