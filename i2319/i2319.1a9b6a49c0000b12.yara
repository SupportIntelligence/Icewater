
rule i2319_1a9b6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.1a9b6a49c0000b12"
     cluster="i2319.1a9b6a49c0000b12"
     cluster_size="60"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="exploit cmpztx expkit"
     md5_hashes="['380c2a1d0386dff2580611ddd5f498444c30c8be','4d9da32d6cab07275d2333e03090cd38bbdd3515','616b8e9d9a62622b28ea4043222f9bfd3dbd35ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.1a9b6a49c0000b12"

   strings:
      $hex_string = { 20537472696e67223b4f6c6c6c4f4f3d2274696f6e223b4f6c4f6c6c4f3d22436f64652878297d223b4f6c6c4f4f4f3d2243686172223b4f6c6c6c4f6c3d2266 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
