
rule k2321_29651162d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29651162d9eb1912"
     cluster="k2321.29651162d9eb1912"
     cluster_size="6"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['1eba04ccfb474c2cc79f7e0d73bd6077','2d43e9c14df03506c77c97ce4e75ad4c','f973b74ab0f69c4d9063d71cb089f079']"

   strings:
      $hex_string = { dc404a979f8ca1805f4408f845c75dd6c671265235eeb4e51a6ccb9bb12d7f1879d57723a3e4b84b6027398a2505dcd35a0b74aac15e6d03bebb19c55e55fcec }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
