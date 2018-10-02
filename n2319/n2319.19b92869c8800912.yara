
rule n2319_19b92869c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.19b92869c8800912"
     cluster="n2319.19b92869c8800912"
     cluster_size="114"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitcoinminer coinminer miner"
     md5_hashes="['9be038c0ecb13c058b4cdcc7330cc829451676bb','edb95dd7922c37e1555cc5e9be3121416c4d883e','87767b1fbcf6a94b7ba1fb4f3e64e0e86d8820e0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.19b92869c8800912"

   strings:
      $hex_string = { 62262621722e6973456d7074794f626a6563742862297d7d3b76617220573d6e657720562c583d6e657720562c593d2f5e283f3a5c7b5b5c775c575d2a5c7d7c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
