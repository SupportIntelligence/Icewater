
rule j2319_039b6a17ba230932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.039b6a17ba230932"
     cluster="j2319.039b6a17ba230932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script megasearch"
     md5_hashes="['e0b83ef6b44623e4c3a7db5e13de1ff0fc33af29','4714f1e438b89a0dddb562663c287da0e94e9483','e798e6f2ce94e7ef997618b14c2680aaea7e518e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.039b6a17ba230932"

   strings:
      $hex_string = { 2e67657454696d6528292f314533297d7d63617463682863297b72657475726e20307d7d7d2c6462636c6173733d7b656e67696e65733a5b227072666462222c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
