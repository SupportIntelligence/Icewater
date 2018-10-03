
rule ofc8_5918a84bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.5918a84bc6220b12"
     cluster="ofc8.5918a84bc6220b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['7ddaf47390983b12ad943899472dc50cc07493d4','e8c8376415f0debc09ef43f979e9234136365be7','9e5a7253cd3b8bcae869b1d16c256c66a1b5b9ea']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.5918a84bc6220b12"

   strings:
      $hex_string = { 96471a092cc3d6c2d5edc456dd6010988fbbb14cbe8093dbc9ae26a320df46e00bf35e0c0f716d7737e57c977d94a6a963c8f4ab36faec2a8d257b3f57280abc }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
