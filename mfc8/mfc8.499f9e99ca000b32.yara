
rule mfc8_499f9e99ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=mfc8.499f9e99ca000b32"
     cluster="mfc8.499f9e99ca000b32"
     cluster_size="248"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos backdoor hiddenapp"
     md5_hashes="['ffd742aac65d36709fa51dcc2b29c3ed423ec6e1','44789118aba6ce9b94c7313c8e34ebbebd61049e','4303ebbfb1312eb3301ad065011e95684dde813f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=mfc8.499f9e99ca000b32"

   strings:
      $hex_string = { 75acf1e103b95c67ffa9fc289aaefeb3f2e3c263f61aa5535608e66bcf733cf87461d494bee0e7cc864d8c278009e90830ef1b342e18bc99005ada20154ea839 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
