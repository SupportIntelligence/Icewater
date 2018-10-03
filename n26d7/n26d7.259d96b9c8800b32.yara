
rule n26d7_259d96b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.259d96b9c8800b32"
     cluster="n26d7.259d96b9c8800b32"
     cluster_size="54"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="xcnfe malicious genx"
     md5_hashes="['199178794360d56ce6d0707581a6945b45d2ebd1','c6cd05c9b227f66c4e0cd498bb4a9e282f4ccb62','d80bc5531b49ff25fe8d6e6d4eb890feb3fafd84']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.259d96b9c8800b32"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
