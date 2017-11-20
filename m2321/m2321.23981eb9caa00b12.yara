
rule m2321_23981eb9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.23981eb9caa00b12"
     cluster="m2321.23981eb9caa00b12"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hackkms riskware risktool"
     md5_hashes="['0e6890a19435e4ae0e2947b41c703d57','407ad55dec614a7868c31a2c24e6eaff','f764ceb55c2177615736f1ade6702b01']"

   strings:
      $hex_string = { bfdd379f56e2f357ded632978ccbf1b11bd3e6947d9e68b43d6714a6e708c2d8ba89d102ada04c0ff8246507f9f2729717a75a8f5cb2a5092596f6bc1369e952 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
