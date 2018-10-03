
rule k2319_399996b9ca800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.399996b9ca800b32"
     cluster="k2319.399996b9ca800b32"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['0781eb451401de673be34a3187082616e086831b','330f1d7af5b1eb385a8f34c84f07f0fba720d3dc','d41aee12682d0ff24a97ae9921887eda6db08617']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.399996b9ca800b32"

   strings:
      $hex_string = { 0a0a3c212d2d20626f6479202f2f2d2d3e0a3c7461626c6520626f726465723d2230222077696474683d2231303025222063656c6c73706163696e673d223322 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
