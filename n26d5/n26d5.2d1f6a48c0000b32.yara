
rule n26d5_2d1f6a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d1f6a48c0000b32"
     cluster="n26d5.2d1f6a48c0000b32"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['4eaeb49e257a95321707fc519480041e7e8709f5','f1e98aad803ee7aa42b9b1449708d1ab9f8aa320','cec05419fcd6fab321c9c5351f634c7015422920']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d1f6a48c0000b32"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
