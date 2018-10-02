
rule k2319_39129cb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39129cb9c8800b12"
     cluster="k2319.39129cb9c8800b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['230ce67e3879144f4916f152d909b7000e343c78','ace94c77416e223fb7b8eb54098c397dfc028b8e','fd71845d3a2ad46d5e4b83f6e98f274dc6b04306']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39129cb9c8800b12"

   strings:
      $hex_string = { 756e646566696e6564297b72657475726e20445b655d3b7d76617220503d282830783141442c342e36324532293e2830783131312c38322e293f2833352e3745 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
