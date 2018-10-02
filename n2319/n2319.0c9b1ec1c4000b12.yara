
rule n2319_0c9b1ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.0c9b1ec1c4000b12"
     cluster="n2319.0c9b1ec1c4000b12"
     cluster_size="35"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitcoinminer coinminer miner"
     md5_hashes="['66f517aa73888b673d9db56bb79565a72fbbf66e','6a1d46d5bcdc8c391da6d3b17606ea4d3e3aedeb','8116ba51652ee98100f7a296dfacfb0ee9e40ae6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.0c9b1ec1c4000b12"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
