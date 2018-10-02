
rule o26bb_07c3d4e1c6000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.07c3d4e1c6000b12"
     cluster="o26bb.07c3d4e1c6000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious gamehack unsafe"
     md5_hashes="['5673d98d4f97e773cdde9125bffff039e1540359','f8fff7765b6858bba1d524805e511ffb061fa664','f588035c2a5b71b800cabc50e3f631033902ab91']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.07c3d4e1c6000b12"

   strings:
      $hex_string = { 45018bcf2bca415333dbd1e93bfa1bfff7d723f976118d6424008a0a8d5202880843403bdf72f3c6460b085beb3980f9100f85fc000000837c24180074058d55 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
