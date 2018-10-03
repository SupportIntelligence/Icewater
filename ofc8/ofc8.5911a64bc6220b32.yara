
rule ofc8_5911a64bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.5911a64bc6220b32"
     cluster="ofc8.5911a64bc6220b32"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['5d9d240cb690d182eb1cac9b2a138aac89d21eec','a9172183b75b2e07b409660a33c58962de455237','dd72b0f0e899c730dba20c45d24c8930c5e9ab2a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.5911a64bc6220b32"

   strings:
      $hex_string = { dee3b1b6394d3fc589179f689b4e53adb5cfcdb7235c6079412d7b679396d5524262d75e195dbba09def06bd0a789245b2e03c10a3c8e5300edbab64a9d9a848 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
