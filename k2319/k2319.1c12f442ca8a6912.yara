
rule k2319_1c12f442ca8a6912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1c12f442ca8a6912"
     cluster="k2319.1c12f442ca8a6912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script fffazo"
     md5_hashes="['1d2fce9621b3929815373056ddfa33aa32f70851','31bd448bcda4c0031a7aaf3978b1d8b5533eb2bf','12206cb3bcd9e167313f6436e6b19b5f17dae4f5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1c12f442ca8a6912"

   strings:
      $hex_string = { 66696e6564297b72657475726e206f5b4c5d3b7d76617220653d2828312e353645322c3078314339293e3d307834353f28382e2c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
