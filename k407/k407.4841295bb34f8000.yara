
rule k407_4841295bb34f8000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k407.4841295bb34f8000"
     cluster="k407.4841295bb34f8000"
     cluster_size="69"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="adload nsis score"
     md5_hashes="['0614f58d1e22578a4b715e93473a52a3f3049cfe','030765cc4ed2abd40171b80f64e52eeb13b8cabb','0a4e3c21afff827fb5323fe60d58c0964da4d9d4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k407.4841295bb34f8000"

   strings:
      $hex_string = { 400435043604340451043d042000340438044104420440043804310443044204380432042e0000004500720072006f00720020006400650063006f006d007000 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
