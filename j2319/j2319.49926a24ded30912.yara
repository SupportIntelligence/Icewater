
rule j2319_49926a24ded30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.49926a24ded30912"
     cluster="j2319.49926a24ded30912"
     cluster_size="81"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script downldr sload"
     md5_hashes="['7287c78d88130789a3889df84a7db8b660146aad','c678f6068a1e9a1df95ef8c6951dad97870fd2c6','5bdc9d3d64dcdbe451f57e542d043addf1a495cd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.49926a24ded30912"

   strings:
      $hex_string = { 68726c645b31355d2b6d6c7374622e67657a2b706b776d5b305d2b706b776d5b305d2b73656667722e617a6371617d66756e6374696f6e206c75636c2865297b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
