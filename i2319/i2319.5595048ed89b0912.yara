
rule i2319_5595048ed89b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.5595048ed89b0912"
     cluster="i2319.5595048ed89b0912"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="netsnak msexcel catohq"
     md5_hashes="['304908df229f8e1f579d0444f525ed6a7f8d256d','d39013e4e408db5e1d726c51012acb010c64a13d','a113db539be4a6a3d2aa35b7a61b1a9cf990ef4e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.5595048ed89b0912"

   strings:
      $hex_string = { 7274757050617468202620225c6e6f726d616c2e786c6d220d0a456e642049660d0a4e6578740d0a466f722069203d203120546f20576f726b626f6f6b732e43 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
