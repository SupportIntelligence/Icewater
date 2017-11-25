
rule j3f4_090ee128c0800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.090ee128c0800b32"
     cluster="j3f4.090ee128c0800b32"
     cluster_size="652"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy agbf asvcs"
     md5_hashes="['000a1fd3166419daefc52101e1533f0f','002ee20badb5329ebaff003c0b899145','054ea83b952b45a03047d107bcafa38f']"

   strings:
      $hex_string = { ff96e8ffff94e8ffff92e7ffff91e7ffff8fe7ffff8ee6ffff8ce6ffff8be6ffff58ccefff4fc8ecff47c4e9bf0000000000000000000000004acbeeff99e9ff }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
