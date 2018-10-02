
rule k2319_501a96b9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.501a96b9ca200b12"
     cluster="k2319.501a96b9ca200b12"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['fd4a05ed21e74001fa445339506fb5bcfa8a0d44','6ff56875ed38f439b180ad0554edb292275c1f4a','3f30be9ffb5edfb8019665dfa34b5d01d160d059']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.501a96b9ca200b12"

   strings:
      $hex_string = { 3c392e313645323f28372c313139293a2831372c3078313646292929627265616b7d3b7661722042315130763d7b27453076273a66756e6374696f6e284b2c47 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
