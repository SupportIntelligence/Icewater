
rule o26bb_632da1b4dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.632da1b4dda30912"
     cluster="o26bb.632da1b4dda30912"
     cluster_size="63"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['fc5f1f528ad77f722a26da7375aeaaf4dfcac073','31b746ba2e8f57a577e8d9775f92c8824350d0ee','c88194f28db043839ebd71a12d877c3f7fbed323']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.632da1b4dda30912"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
