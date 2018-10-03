
rule ofc8_5918aa4bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.5918aa4bc6220b12"
     cluster="ofc8.5918aa4bc6220b12"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['fbf7532cbccc774c4805b38586e6d57a01843714','77903e9df4600bde2bc44ccc30ebe4b263864474','6eb84304d7253bd2eddc9e4ada4e3a374653ad59']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.5918aa4bc6220b12"

   strings:
      $hex_string = { 96471a092cc3d6c2d5edc456dd6010988fbbb14cbe8093dbc9ae26a320df46e00bf35e0c0f716d7737e57c977d94a6a963c8f4ab36faec2a8d257b3f57280abc }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
