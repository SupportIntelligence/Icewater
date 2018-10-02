
rule n26bb_1b9a1ec9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1b9a1ec9cc000b32"
     cluster="n26bb.1b9a1ec9cc000b32"
     cluster_size="81"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="softonic softonicdownloader malicious"
     md5_hashes="['a603a16c5463dd5e90fdf7c63bd6246d7ff2cb27','896c47bba5abfaf9b8492765e5a6dd2b7d4bf626','1a5139db204e6a7cf4ab37fda3d142261f8ea657']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1b9a1ec9cc000b32"

   strings:
      $hex_string = { cf8b457ac07bc92fa09116abe000ad69e1ffc7efb14e8f08b844a472def38a95fd6d707f1f73192bd1ea99af9d31da595584c81232f00b6276464a18d9b40ea5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
