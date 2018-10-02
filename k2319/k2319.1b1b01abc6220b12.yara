
rule k2319_1b1b01abc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1b1b01abc6220b12"
     cluster="k2319.1b1b01abc6220b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['34444e624ab1127080e9f5ee46788fec61a2c39a','1a8265cc393d3530cfb02c3de93a404dc337e58b','15caae4bad2fd171c6d9784f356e5d0bd2a8eef6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1b1b01abc6220b12"

   strings:
      $hex_string = { 3078313534292929627265616b7d3b666f72287661722051386d20696e206e3643386d297b69662851386d2e6c656e6774683d3d3d2828312e34303945332c32 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
