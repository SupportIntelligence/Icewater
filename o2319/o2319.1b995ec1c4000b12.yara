
rule o2319_1b995ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.1b995ec1c4000b12"
     cluster="o2319.1b995ec1c4000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner coinhive"
     md5_hashes="['b5296c3a966d1d016c21919449bf40270ed0f346','47b2fa6cf08d8679bfbd2b4cab53dbce62ee87bb','1872c9bd6e7b0f6400259a7710e59d1bb09ea4d9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.1b995ec1c4000b12"

   strings:
      $hex_string = { 327c756c297c65722869637c6b30297c65736c387c657a285b342d375d307c6f737c77617c7a65297c666574637c666c79285c2d7c5f297c673120757c673536 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
