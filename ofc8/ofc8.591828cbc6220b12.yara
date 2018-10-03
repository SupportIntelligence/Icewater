
rule ofc8_591828cbc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.591828cbc6220b12"
     cluster="ofc8.591828cbc6220b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['a5204763976f099a2f1f41d82361225fee37bad7','8fff11a27a4d50f071ea07581c90462c3ecfec70','32da75829c65afbf229289c7e308327b8669b90c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.591828cbc6220b12"

   strings:
      $hex_string = { 96471a092cc3d6c2d5edc456dd6010988fbbb14cbe8093dbc9ae26a320df46e00bf35e0c0f716d7737e57c977d94a6a963c8f4ab36faec2a8d257b3f57280abc }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
