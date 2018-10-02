
rule j2319_5b99e90cea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.5b99e90cea210912"
     cluster="j2319.5b99e90cea210912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script sload cloxer"
     md5_hashes="['29d08536fdde08ec935081dd4d8d99cde99ce5c3','1331763909198efb58481badee06aa5eb1e441e8','cf3ee19881818eb7232b9096e97ee4fc68741f26']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.5b99e90cea210912"

   strings:
      $hex_string = { 6172206e3d5b373631392c3238332c652c6371772822764133436b33767667533b44464d22295d2c743d2869726b766d2822532d644e564f652a514755542229 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
