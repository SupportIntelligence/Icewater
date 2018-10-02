
rule k2319_18531ce9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18531ce9c8800912"
     cluster="k2319.18531ce9c8800912"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a1232bdd3a224252325c457c6d66fea594d223a3','c1a104370c570ef4ee24950e26788a4bc64033ec','2924da38ea54d8eb0af16b3d9338019f3dc22234']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18531ce9c8800912"

   strings:
      $hex_string = { 66696e6564297b72657475726e20475b6b5d3b7d76617220763d282830783135412c38352e31304531293e3d2834372e2c3532293f2833362e3745312c307863 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
