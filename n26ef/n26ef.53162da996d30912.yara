
rule n26ef_53162da996d30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26ef.53162da996d30912"
     cluster="n26ef.53162da996d30912"
     cluster_size="2041"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitminer coinminer risktool"
     md5_hashes="['4cd65becf5883c0b49192074872a3b4e46181ebd','1e37683053e12cdaffe9e7a165f47a77846271ea','3ba1d31a677fcb9211d5be5c75198f1796e17768']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26ef.53162da996d30912"

   strings:
      $hex_string = { 4c8d3decc7fdff897c247083f9090f85950200008d479c3df30100007731b81f85eb518bcff7e7c1ea056bc264448bc24d03c02bc88bd94b399cc730ac070076 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
