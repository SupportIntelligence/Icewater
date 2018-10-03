
rule i2319_15b0cbb9d934e131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.15b0cbb9d934e131"
     cluster="i2319.15b0cbb9d934e131"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html script"
     md5_hashes="['e6de2271e2eee064b34e7278fa09de54b60140ca','4cd9f59434dc185735f1f16dfbf627ad2e00a0ad','57f6084789ec46651b83c02eb0f083621eebcf42']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.15b0cbb9d934e131"

   strings:
      $hex_string = { 772e77332e6f72672f313939392f7868746d6c223e0d0a3c686561643e0d0a3c6d65746120687474702d65717569763d22436f6e74656e742d54797065222063 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
