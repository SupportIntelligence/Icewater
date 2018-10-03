
rule n2319_6994d1e1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6994d1e1c2000b12"
     cluster="n2319.6994d1e1c2000b12"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinhive"
     md5_hashes="['704b5c8af80b57bc3bd21e7078acd9bbe27f5732','0ad2f7c026c4de4ef69631757833632b9ee9b356','9ad0815d5d0afc14aaeba720b25d334940d31ad5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6994d1e1c2000b12"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
