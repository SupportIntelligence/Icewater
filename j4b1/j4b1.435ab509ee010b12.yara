
rule j4b1_435ab509ee010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j4b1.435ab509ee010b12"
     cluster="j4b1.435ab509ee010b12"
     cluster_size="245"
     filetype = "video/mp4"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['003ddd1c7d719d0f2e0133f1f7f26d9f','006a21e32ad660586e7dd517234b3386','13534cd47e1a8a03c594f53b64ad20a7']"

   strings:
      $hex_string = { 02000aaf52000b8a24000c4238000d2977000dfc75000ed412000fb3ce001082a100113efa0011d8260012cd450013c4a60014e09d0015f2f00016e24b0017aa }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
