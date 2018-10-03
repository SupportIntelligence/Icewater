
rule n26d5_2d94ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d94ea48c0000b12"
     cluster="n26d5.2d94ea48c0000b12"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['637fab64d0da2cd412ff4b6e4cb470217e4c1466','237af54c51d3b7dd88e8a40a08119c5c6003a2da','87e6490683406e0f3a29a176125b830d8abb9a1f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d94ea48c0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
