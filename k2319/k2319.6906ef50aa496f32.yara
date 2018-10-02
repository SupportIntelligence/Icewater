
rule k2319_6906ef50aa496f32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6906ef50aa496f32"
     cluster="k2319.6906ef50aa496f32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script asmalwsc"
     md5_hashes="['8029a68b66d67ba828ccbb52a46f4b6d43c8c71e','83b718614ec6ae414ab81dc292c258f4a053c88f','d8b9de7001791c4ceabf8a9b46f1df8ef3c76093']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6906ef50aa496f32"

   strings:
      $hex_string = { 66696e6564297b72657475726e20465b765d3b7d766172204a3d2828307834352c3836293c3d312e33373745333f28307844362c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
