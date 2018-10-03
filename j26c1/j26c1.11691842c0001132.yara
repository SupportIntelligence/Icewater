
rule j26c1_11691842c0001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26c1.11691842c0001132"
     cluster="j26c1.11691842c0001132"
     cluster_size="2928"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linux silly unix"
     md5_hashes="['a4de280192e83b6283a3b50a74d6b082ee3130f4','c5e83a0a2635423e96b23b1238ff39366fe8c20e','608340cbd59d6b127ded915a2c5ac496f3176156']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26c1.11691842c0001132"

   strings:
      $hex_string = { 83c40c85db7c1353568b550c52e85affffff39d8750431c0eb05b8010000008da5f4efffff5b5e5f89ec5dc35589e581ec9c0000005756538b5d186a00e819fe }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
