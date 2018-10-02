
rule n3f8_4d22de4ccb401132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.4d22de4ccb401132"
     cluster="n3f8.4d22de4ccb401132"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos dldr entxvm"
     md5_hashes="['5e4987f316005a8b23772f08a4b1126805122238','fd321269a26eb693d3a79d75f054dfbca75f24bc','f249a8213032bc631af0622f5a0a033c551084f6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.4d22de4ccb401132"

   strings:
      $hex_string = { 64792f50696e673b00324c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f737064792f507573684f6273657276657224313b00304c63 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
