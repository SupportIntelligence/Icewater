
rule k2319_18099cb9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18099cb9c8800912"
     cluster="k2319.18099cb9c8800912"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script kryptik diplugem"
     md5_hashes="['ea07c1af900dfbb1feb949f1859309332408c749','b37819562644eef62c6efa79c66c45fc0f4b7300','758941c9fa1474f67d4a94f6d5f6b8436f4b92c8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18099cb9c8800912"

   strings:
      $hex_string = { 696e6564297b72657475726e204e5b505d3b7d7661722075393d2828307842372c3078313638293c3d34372e3645313f28312e31353145332c30786363396532 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
