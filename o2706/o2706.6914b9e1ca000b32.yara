
rule o2706_6914b9e1ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2706.6914b9e1ca000b32"
     cluster="o2706.6914b9e1ca000b32"
     cluster_size="46"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsefox yontoo malicious"
     md5_hashes="['fc40c5f4abdd5a0ae7e58779bd012351638c20ed','3f1a41c0f00e056e8748c4443f010fa0119715ff','aff146b47ad1c6f67f368591f73f8954f54f53a8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2706.6914b9e1ca000b32"

   strings:
      $hex_string = { 316434653433373839623239333539323933613066363434616663006d5f506c7567696e546872656164006d5f56657273696f6e00496e697469616c697a654c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
