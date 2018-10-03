
rule o26d7_5bb29a58d78bdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.5bb29a58d78bdb12"
     cluster="o26d7.5bb29a58d78bdb12"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="soft barys malicious"
     md5_hashes="['6fe9a1810aab4076ce2adbc695d2760127a809f5','3af67ac9add283a408e5ca9e3b24f3595ba3a780','c62e2b1e2adae67c0978dc12638255e1d512396f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.5bb29a58d78bdb12"

   strings:
      $hex_string = { fce8b61efbffc3e9fcdbfaffebd35f5e5b8be55dc2040000d85332b02077684bb10ae3e79b91ecd3175f39d0aa52154593a55b292f03aa7b8aea5d2865b8d111 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
