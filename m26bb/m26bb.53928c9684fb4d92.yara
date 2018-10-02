
rule m26bb_53928c9684fb4d92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.53928c9684fb4d92"
     cluster="m26bb.53928c9684fb4d92"
     cluster_size="93"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="swisyn malicious attribute"
     md5_hashes="['9951c9f3751be8dd4f8404c2410da221ca4b8025','b01a605d6c8dba9a22caf6c84607b88561e8e38f','496b3c2d0a8bac2ef10844c6986d21446c51654e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.53928c9684fb4d92"

   strings:
      $hex_string = { eba900dadea9001c90b7001f4e62001568a5001878ba00e8f5a900fff7ad00e2eb9c00d2d2940033a2c7003192ba0046ccef00d6eb8c00d6e597002d6f71002e }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
