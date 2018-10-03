
rule j2319_039b6c0e9ee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.039b6c0e9ee30932"
     cluster="j2319.039b6c0e9ee30932"
     cluster_size="49"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="megasearch diplugem multiplug"
     md5_hashes="['0912ef9fe9c163289f1e18f0071f6f657c9c6ed8','2a06cd7671b950bfd2210bb0cd78d6fd1fd038d8','bded53172edb25943d26073c453ed56a0833a9f0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.039b6c0e9ee30932"

   strings:
      $hex_string = { 2e67657454696d6528292f314533297d7d63617463682863297b72657475726e20307d7d7d2c6462636c6173733d7b656e67696e65733a5b227072666462222c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
