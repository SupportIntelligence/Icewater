
rule k2319_1101496986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1101496986220b12"
     cluster="k2319.1101496986220b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['73772f3b34d086e4f7302b588176f15768cdd2ce','d5a260b317c7148e38a4e31a97db5501de7b725d','de9b1d147036a6b5c94cceb0ada5d7bcba4506c8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1101496986220b12"

   strings:
      $hex_string = { 3d756e646566696e6564297b72657475726e204c365b745d3b7d766172206c3d2828322c372e36354532293e2830783144352c392e31334532293f2754273a39 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
