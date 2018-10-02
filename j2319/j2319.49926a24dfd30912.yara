
rule j2319_49926a24dfd30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.49926a24dfd30912"
     cluster="j2319.49926a24dfd30912"
     cluster_size="299"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script downldr sload"
     md5_hashes="['8e30a970aced2f380acc2e566b41c376b99f9e57','e28b3de187cad53262b2137c61f425a4c7f8cda3','554addd873aae2c5069a33beaee07926107555d0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.49926a24dfd30912"

   strings:
      $hex_string = { 68726c645b31355d2b6d6c7374622e67657a2b706b776d5b305d2b706b776d5b305d2b73656667722e617a6371617d66756e6374696f6e206c75636c2865297b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
