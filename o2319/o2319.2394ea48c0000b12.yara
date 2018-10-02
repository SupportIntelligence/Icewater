
rule o2319_2394ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.2394ea48c0000b12"
     cluster="o2319.2394ea48c0000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker autolike classic"
     md5_hashes="['b97cb6e46a75ff5141c7cbba8276606dcba61c26','e3bfa9b8eb61244cfb5cf5a413b21f15006b63f3','6e02203498a486636323920b1fb726d564ab238a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.2394ea48c0000b12"

   strings:
      $hex_string = { 313b72657475726e21307d6b2e6572726f722865297d2c4348494c443a66756e6374696f6e28612c62297b76617220633d625b315d2c643d613b737769746368 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
