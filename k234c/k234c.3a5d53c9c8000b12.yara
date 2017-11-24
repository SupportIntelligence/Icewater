
rule k234c_3a5d53c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k234c.3a5d53c9c8000b12"
     cluster="k234c.3a5d53c9c8000b12"
     cluster_size="4"
     filetype = "Algol 68 source"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script classic expkit"
     md5_hashes="['1c23958b4715b262e372f97fd5e85cb0','20eed1a2076d9c7f7ae67e13492d5667','f6bb9010f42d36556c2364321a4fe55a']"

   strings:
      $hex_string = { 657220626c6f636b2077697468206e6f6e636520284e4953542053503830302d33384120c2a7422e32293a205b302d315d203d206d696c6c697365632c200d0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
