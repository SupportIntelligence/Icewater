
rule j2319_439e9599c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.439e9599c2200b12"
     cluster="j2319.439e9599c2200b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="nemucod script dloade"
     md5_hashes="['40dea858f7bbe23d0ebeacdda0e4534782759c5a','d9b79b809cf8a5b4cd52fe351f4a64a78fcf98c4','04c210bfbe3edeefa9e5f7d6ba42d9876d4c10cf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.439e9599c2200b12"

   strings:
      $hex_string = { 352b4150764f6535445332724f642f4c7273395870665a386b464537774e6c70324e4967636f41304b6a6a540a71756e736a44335173526f6269706d56674334 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
