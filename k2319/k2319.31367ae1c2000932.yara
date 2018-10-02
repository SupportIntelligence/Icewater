
rule k2319_31367ae1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.31367ae1c2000932"
     cluster="k2319.31367ae1c2000932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['522491f506cec0b14716e63ee276a79327ecaa4d','f72b32c17142d8ef84ccc08d02175c1bcd13d423','6b3f0d16637cf3b2c440cb851e6eb23e35a83f14']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.31367ae1c2000932"

   strings:
      $hex_string = { 3139293a2831302e343345322c34352e292929627265616b7d3b7661722067364b343d7b275a3066273a66756e6374696f6e28482c47297b72657475726e2048 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
