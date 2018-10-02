
rule n3f8_6d2ace166d210122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6d2ace166d210122"
     cluster="n3f8.6d2ace166d210122"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos dldr entxvm"
     md5_hashes="['f6a75a9fcb4d745bef2c8c2f2b26b0f7102bd0ce','2bd24e1b043fe748b14c3ee77508b54110780196','cab75e2ad9729fde0df7b416184b3dfaf34a77a9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6d2ace166d210122"

   strings:
      $hex_string = { 64792f50696e673b00324c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f737064792f507573684f6273657276657224313b00304c63 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
