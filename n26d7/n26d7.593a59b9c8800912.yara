
rule n26d7_593a59b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.593a59b9c8800912"
     cluster="n26d7.593a59b9c8800912"
     cluster_size="46"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="xcnfe malicious genx"
     md5_hashes="['d5e6e96cbd1b9f0a84500650e216abb865b20d72','5b6dca6d8cb4864f8113f269cdfd129931f13673','9056a631cc39626a28d8f88eb4d587530f90e892']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.593a59b9c8800912"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
