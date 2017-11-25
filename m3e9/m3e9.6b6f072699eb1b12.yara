
rule m3e9_6b6f072699eb1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b6f072699eb1b12"
     cluster="m3e9.6b6f072699eb1b12"
     cluster_size="24"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['0f452783e74ea2aebceed4c5a07c5093','1d85089c02bed542f714d8b0eb152902','c29529e7d8171256480f943fca6a4649']"

   strings:
      $hex_string = { be3046adf7ca4aef457783f2905e7ab552e7907439ddea9160f3314ea9a6e37e8563c4c0a784950b11332b2ceea2e2bb3ff0d2b71cf8d73202b1621e5cbfe561 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
