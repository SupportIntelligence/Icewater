
rule i2320_1194a214c2427b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2320.1194a214c2427b12"
     cluster="i2320.1194a214c2427b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="exploit msoffice expl"
     md5_hashes="['9937ebd2d4a02b9ee96b88d2e28fd8002cd9072c','49f7483906e7a4a09516eb815ff03293c9b41aa2','8869b1b365287f0299b3a03c152536341d1f227d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2320.1194a214c2427b12"

   strings:
      $hex_string = { 922aa863912b45b534e31098246191e85fdae14dab061e0dea31dbb0bf114176b5ce14e5c356bcf09defb28c7824cb0f39dc5d5c59779390541096cdd9bbcf4f }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
