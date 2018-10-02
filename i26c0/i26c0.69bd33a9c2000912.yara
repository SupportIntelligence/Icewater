
rule i26c0_69bd33a9c2000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26c0.69bd33a9c2000912"
     cluster="i26c0.69bd33a9c2000912"
     cluster_size="226"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy malicious exad"
     md5_hashes="['5b714a5ccb57421650c14dc8b19bbefeb4146c50','97ca4068dbbfdab7a1e1c007bf0927f4a5c94389','afe29ec433a7e0f7f14bb7fbfd9b8870534df35e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26c0.69bd33a9c2000912"

   strings:
      $hex_string = { fa74464975d6c9c20800253038780a005375636365730a005f25732e6578650031c0eb07eb8b642408eb03ebf874648f00eb06e983c404eb03ebf9eb61686f02 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
