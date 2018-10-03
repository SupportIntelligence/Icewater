
rule k2319_295a8699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.295a8699c2200b12"
     cluster="k2319.295a8699c2200b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['561b15b8b7f176a7e823dc32888ef96004bdfb1f','a9bde01d345103c79b1ee1a340b60fe14d9c14ff','747dc37defae23a5ec59118125c7d1a1e1c76c5a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.295a8699c2200b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20505b6a5d3b7d76617220753d28283132352e2c322e30374532293c3d283134362c3078323343293f2835332e2c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
