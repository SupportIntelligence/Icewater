
rule ofc8_5b15a64bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.5b15a64bc6220b32"
     cluster="ofc8.5b15a64bc6220b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['72f015373418600e34b573a438294f4142d2075d','1cdf812c8760000de5086025a552c7d534abd10e','44a185b576e8e046f6ba337492bc6c1c610a9093']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.5b15a64bc6220b32"

   strings:
      $hex_string = { dee3b1b6394d3fc589179f689b4e53adb5cfcdb7235c6079412d7b679396d5524262d75e195dbba09def06bd0a789245b2e03c10a3c8e5300edbab64a9d9a848 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
