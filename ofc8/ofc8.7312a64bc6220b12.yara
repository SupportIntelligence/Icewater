
rule ofc8_7312a64bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.7312a64bc6220b12"
     cluster="ofc8.7312a64bc6220b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['4066c895c930b325f5563029c8ab352092e4f34e','fedccce173f11a1937c3e12e834c0efe9e4f2a60','f0c252d984cc99a7c18d027644fb272efe73274d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.7312a64bc6220b12"

   strings:
      $hex_string = { dee3b1b6394d3fc589179f689b4e53adb5cfcdb7235c6079412d7b679396d5524262d75e195dbba09def06bd0a789245b2e03c10a3c8e5300edbab64a9d9a848 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
