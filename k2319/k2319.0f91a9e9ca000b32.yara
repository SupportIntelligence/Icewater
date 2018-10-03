
rule k2319_0f91a9e9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.0f91a9e9ca000b32"
     cluster="k2319.0f91a9e9ca000b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector script html"
     md5_hashes="['42ad5d718cced5b5288a6568ea846a5d99b7adb1','d33200e73dc3708951f96f90fa68d0f919854a13','21378459fc479c3a70f1988285faf453a298a85d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.0f91a9e9ca000b32"

   strings:
      $hex_string = { 61672e646566696e65536c6f7428272f39353936333539362f414e475f62656c6f775f3732385839305f646670272c205b3732382c2039305d2c20276469762d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
