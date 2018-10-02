
rule n2319_11993841c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.11993841c8000932"
     cluster="n2319.11993841c8000932"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker script"
     md5_hashes="['da01b2c6a98479000e1cc02328f0a0b2bdbd7f2e','af3871ddddbce6d0d80eab3179227ca81f4f9be0','320a96bdf77b3e359ad771b095e18c76b5dcadf4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.11993841c8000932"

   strings:
      $hex_string = { 297d3b766172206b623d6465636f64655552492822253733637269707422292c6c623d2f5e5b2d2b5f302d395c2f412d5a612d7a5d2b3d7b302c327d242f2c6d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
