
rule k3e9_292d1962d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.292d1962d9eb1912"
     cluster="k3e9.292d1962d9eb1912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt barys"
     md5_hashes="['2a8a2d2655d0250eb826947fa35d0a2d','2d8838e6de607662ed4858504140256e','ab138ce44e311c86383e740fa7571439']"

   strings:
      $hex_string = { dc404a979f8ca1805f4408f845c75dd6c671265235eeb4e51a6ccb9bb12d7f1879d57723a3e4b84b6027398a2505dcd35a0b74aac15e6d03bebb19c55e55fcec }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
