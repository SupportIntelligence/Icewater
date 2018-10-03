
rule i2319_15b0c3b9d934e131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.15b0c3b9d934e131"
     cluster="i2319.15b0c3b9d934e131"
     cluster_size="123"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html script"
     md5_hashes="['a4a15be60e3358a4771dd0efc6dbc0d11bc50d9b','a40d842e8e454c335039da72027620c6de664738','b5e6e55b3835652edc491db09cb0331c98c767ba']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.15b0c3b9d934e131"

   strings:
      $hex_string = { 772e77332e6f72672f313939392f7868746d6c223e0d0a3c686561643e0d0a3c6d65746120687474702d65717569763d22436f6e74656e742d54797065222063 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
