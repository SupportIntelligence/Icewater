
rule k2319_395936e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.395936e9c8800b12"
     cluster="k2319.395936e9c8800b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['64e8510b4029c9532e879d12d62a21155bf15fc8','e9df54e4b46391019e6b89722729302fc01118a6','f09520069cfa829c9a64ffc8db0ff2e03686de02']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.395936e9c8800b12"

   strings:
      $hex_string = { 6e646566696e6564297b72657475726e20705b535d3b7d76617220523d28283134342e3545312c3078323141293e3134323f28312e33343145332c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
