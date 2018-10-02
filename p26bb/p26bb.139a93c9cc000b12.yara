
rule p26bb_139a93c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.139a93c9cc000b12"
     cluster="p26bb.139a93c9cc000b12"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu malicious heuristic"
     md5_hashes="['13bbcd5b904da58d0fd7ee110611232c010be7a5','13d3c6dc39195a5595e83ec799be469972f3c84a','73d878d450ec53e89b6bdc57ba78169e3fd3581d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.139a93c9cc000b12"

   strings:
      $hex_string = { df932ef96ab757990c78e8b11d16d886880429973b05963001f71043fe69651faeac6fd6ffd05ad5dd58e31cf3c154a3a55ba82fea2367ade44e9a3e195356bb }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
