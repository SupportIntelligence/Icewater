
rule j26d4_14a26b2bcac3f17a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26d4.14a26b2bcac3f17a"
     cluster="j26d4.14a26b2bcac3f17a"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="proxy malicious atraps"
     md5_hashes="['49f0ea873620ad89f12e065bb6402bad10688735','7a26fe999dbabbbf676fee2ff50882af13e96bf6','9cce4b1e89ed8d3ea20209219316d9eeaa566e2c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26d4.14a26b2bcac3f17a"

   strings:
      $hex_string = { 4b504646ff374e4e81eb882301005b5883fb000f85fd0900000f84240a0000d3fa589b1d9420b981b42cbe81f22e9381b23cbfcbd20ad747f356c66dab6b2212 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
