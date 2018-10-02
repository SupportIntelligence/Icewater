
rule o2319_491b2949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.491b2949c0000b32"
     cluster="o2319.491b2949c0000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitcoinminer coinminer coinhive"
     md5_hashes="['3739260457fa75cf01a4e7a28039b69f5fbfddef','e39b7cbcceec148cbe63565dfe6a0cfae0095e53','c52b9302628c26976e432e242534d5f7c2189819']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.491b2949c0000b32"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
