
rule n2319_11b913a9ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.11b913a9ca000912"
     cluster="n2319.11b913a9ca000912"
     cluster_size="87"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitcoinminer miner script"
     md5_hashes="['58b3557504dc27ead1f52fa175a0608bc98f3c56','85d38287fe0d1755edb5693c5866578faacb7b4f','5796ea0b4efd031b437aed3181bdbb7e421e8368']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.11b913a9ca000912"

   strings:
      $hex_string = { 74262621772e6973456d7074794f626a6563742874297d7d3b766172204a3d6e657720512c4b3d6e657720512c5a3d2f5e283f3a5c7b5b5c775c575d2a5c7d7c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
