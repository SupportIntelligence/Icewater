
rule k2319_18519699c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18519699c6200b12"
     cluster="k2319.18519699c6200b12"
     cluster_size="86"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d0d0cd4d884fb6c9fa545fb1aa30e17c5670ba31','b24a166925d4bbca305ac7245536364af800eef4','d5b7f6f5a72a460e892f40ace0f1532c6047bf63']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18519699c6200b12"

   strings:
      $hex_string = { 3b7d2c274e3558273a224174222c27773347273a2866756e6374696f6e28297b7661722051303d66756e6374696f6e286b2c432c45297b69662849305b455d21 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
