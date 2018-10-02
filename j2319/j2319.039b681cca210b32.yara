
rule j2319_039b681cca210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.039b681cca210b32"
     cluster="j2319.039b681cca210b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script megasearch"
     md5_hashes="['eb8d606b9ab99bd6c051dfcf4805900917e41c68','bbd99e1a8bbfb88f34644f0a11c2d19e43745f88','1fd69617833ac17d6838e95ebecf5c26a3fea9d1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.039b681cca210b32"

   strings:
      $hex_string = { 2e67657454696d6528292f314533297d7d63617463682863297b72657475726e20307d7d7d2c6462636c6173733d7b656e67696e65733a5b227072666462222c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
