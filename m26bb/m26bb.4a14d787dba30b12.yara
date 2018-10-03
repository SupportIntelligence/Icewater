
rule m26bb_4a14d787dba30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.4a14d787dba30b12"
     cluster="m26bb.4a14d787dba30b12"
     cluster_size="1039"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="backdoor downlite malicious"
     md5_hashes="['b13d36da2c9a2ee4e7382d22cc96348bb1ebac3e','c381a2da514fdc1b43f021ad1213caf491abf8fe','d6fab6a886a3245b72274711550c1c2fb7eab815']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.4a14d787dba30b12"

   strings:
      $hex_string = { 40d36eff48d574ff4fd679ff4fd679ff4fd679ff4fd679ff5fda85ff5fda85ff6bdd8fff71de93ff7de19dff88e4a5de8ce5a8b18ce5a8848ce5a8548ce5a81e }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
