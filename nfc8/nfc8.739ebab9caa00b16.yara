
rule nfc8_739ebab9caa00b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.739ebab9caa00b16"
     cluster="nfc8.739ebab9caa00b16"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos andr apbl"
     md5_hashes="['25027f5fed7ac65a48f3a87b74b5c3668e453797','ea680550feffb239bf2997f508e2b05bee9cbe7a','449aa732ecc9704b3ee3485cfebfa72aea9e9ed0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.739ebab9caa00b16"

   strings:
      $hex_string = { eac7f8777de3a75fa2f3eb839c73882f9461a1f934e47b3be55156474f78369d71ffe731dfb38e63da59e62449abaf43d2ea6b44bd5407c6b7ec916a5c3ac899 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
