
rule n3f8_6d2ace1e6d210122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6d2ace1e6d210122"
     cluster="n3f8.6d2ace1e6d210122"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos boosad dldr"
     md5_hashes="['6565c469086b6b22059867d7f6cb8c159ef39d82','49c8a939a78270460aec0acf73af58fb6672f82a','47eedef5c327363ef0f9e8cc0bccacdca894674f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6d2ace1e6d210122"

   strings:
      $hex_string = { 64792f50696e673b00324c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f737064792f507573684f6273657276657224313b00304c63 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
