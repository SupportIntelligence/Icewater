
rule m2319_5112948bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.5112948bc6220b32"
     cluster="m2319.5112948bc6220b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink script html"
     md5_hashes="['a2121aa4d417203a4ae268fcc782f8b1fde5f68c','34a155e1a0e1ab4e87267c5293edea9400f75753','424fd5b35a68f556a0044e65077a7fd8d139e915']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.5112948bc6220b32"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
