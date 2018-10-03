
rule k2319_18188699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18188699c2200b12"
     cluster="k2319.18188699c2200b12"
     cluster_size="45"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['1679254267931dc3eb2822c2313c7b94504963ed','ce1cc5cec1112c2bdb43342a4e1f63ebf1a61e7d','68b07a2c3928d039c6369692ad182dbdcee04c70']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18188699c2200b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20755b4f5d3b7d76617220473d28307843413c2835322e2c3078323138293f283131372e2c30786363396532643531293a2834 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
