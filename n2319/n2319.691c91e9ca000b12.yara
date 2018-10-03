
rule n2319_691c91e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.691c91e9ca000b12"
     cluster="n2319.691c91e9ca000b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker clicker script"
     md5_hashes="['b7aee548cac41d6390b2500f10cb7908e72d808b','fb70aa98c607c29932fa5790133994133da8f6bd','17526b5db16c36e97220ed2628d0f29a62feb5a8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.691c91e9ca000b12"

   strings:
      $hex_string = { 7b6261636b67726f756e643a75726c28687474703a2f2f342e62702e626c6f6773706f742e636f6d2f2d557a5153567165333530412f55524a68476148734771 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
