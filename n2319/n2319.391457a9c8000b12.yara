
rule n2319_391457a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.391457a9c8000b12"
     cluster="n2319.391457a9c8000b12"
     cluster_size="40"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['97ff5cc79f22c5b12b126f445dd5304b99ae3eec','4ab21701022d5bf0a9b72fe9e6aa07a468a099cf','2c63ae76ab82ee03ab903dc3c6a48620c6c33467']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.391457a9c8000b12"

   strings:
      $hex_string = { 66567857346170535432703727293b0a202020206d696e65722e737461727428436f696e486976652e464f5243455f4d554c54495f544142293b0a2f2f3c215b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
