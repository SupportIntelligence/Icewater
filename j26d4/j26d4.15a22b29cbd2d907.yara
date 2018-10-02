
rule j26d4_15a22b29cbd2d907
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26d4.15a22b29cbd2d907"
     cluster="j26d4.15a22b29cbd2d907"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor malicious proxy"
     md5_hashes="['8c06d4ea2057352b5ff80ff89996973baf9f5a43','711127824f3ab1b1cbcd1307098376f0a394f2aa','d4513dadbbf4f1dbc8cb559c85c00134a31dca00']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26d4.15a22b29cbd2d907"

   strings:
      $hex_string = { 4b504646ff374e4e81eb882301005b5883fb000f85060a00000f842d0a0000d3fa589b1d9420b981b42cbe81f22e9381b23cbfcbd20ad747f356c66dab6b2212 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
