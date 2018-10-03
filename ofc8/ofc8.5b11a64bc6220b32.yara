
rule ofc8_5b11a64bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.5b11a64bc6220b32"
     cluster="ofc8.5b11a64bc6220b32"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['07e73851addaa5c5f36ab3e74ab88b368d1e8bbf','459849a2955fb9f59cde29f07c749380b8efa8cb','0432a5ef00192c8e42c4543f4dce3816cc898787']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.5b11a64bc6220b32"

   strings:
      $hex_string = { dee3b1b6394d3fc589179f689b4e53adb5cfcdb7235c6079412d7b679396d5524262d75e195dbba09def06bd0a789245b2e03c10a3c8e5300edbab64a9d9a848 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
