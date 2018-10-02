
rule n3f8_6da24e969a6b1132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6da24e969a6b1132"
     cluster="n3f8.6da24e969a6b1132"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos apprisk dldr"
     md5_hashes="['04db6fb83970bc99491bca33d80178095627f30f','8e426549825af943515fdde436503bac8212a520','a4c7ac5f904fbb30dc162e7982533c1f7b3f3efd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6da24e969a6b1132"

   strings:
      $hex_string = { 64792f50696e673b00324c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f737064792f507573684f6273657276657224313b00304c63 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
