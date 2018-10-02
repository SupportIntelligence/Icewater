
rule ofc8_11199e69c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.11199e69c8800b12"
     cluster="ofc8.11199e69c8800b12"
     cluster_size="313"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos revo"
     md5_hashes="['5495725f67131f868f777bcca4ee6351a66fa11c','591d3a4dab47743055156d91f02e3865574076f9','18519a440e6d0ba21c2c3af98644f635f1daa741']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.11199e69c8800b12"

   strings:
      $hex_string = { 6a74524e5300010203052b5a7580765b2d04197cd2fcd47d1a6eedfefaf6ee7110b1b311c4fbefb68e82c713b0eb151673eab470c21e1cc0e8c30c0b1f7b2321 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
