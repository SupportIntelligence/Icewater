
rule k2319_3a189ca9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a189ca9c8800b12"
     cluster="k2319.3a189ca9c8800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['15caf9a8e0f04f86862fb075c5539625def113df','a9a79343af0840af2a53e718575b83c318c2fdfd','d6e29ace612994d3fa5be6ce89ffe8fa42c25410']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a189ca9c8800b12"

   strings:
      $hex_string = { 30332e2c35362e292929627265616b7d3b76617220753877313d7b274e3234273a66756e6374696f6e28592c7a297b72657475726e20593c7a3b7d2c27463751 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
