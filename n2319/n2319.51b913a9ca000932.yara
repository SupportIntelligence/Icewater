
rule n2319_51b913a9ca000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.51b913a9ca000932"
     cluster="n2319.51b913a9ca000932"
     cluster_size="37"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['84f2a8adb6a38d25d25908b8c611c1dd0855f3ac','307dc30be88603d3881cf360d05a9d71263d985b','02ab7e65172048809e36c75cca0900c2b34232f0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.51b913a9ca000932"

   strings:
      $hex_string = { 28293b0a696d67725b305d203d2022687474703a2f2f322e62702e626c6f6773706f742e636f6d2f2d7569745837524f507454552f5479762d47344e415f7549 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
