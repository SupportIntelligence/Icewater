
rule j26f3_435ab509ee210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26f3.435ab509ee210b12"
     cluster="j26f3.435ab509ee210b12"
     cluster_size="625"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family=""
     md5_hashes="['73c55e62aa0b7c0a133f31836360e7ae4ddb8c1b','a0a3a992640decab84c202163ea00823f801f8dc','d1d6ccabd3ccd5e32ca7d12e18786d8fd87bc4f8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26f3.435ab509ee210b12"

   strings:
      $hex_string = { 641f000180b500028d2f0003862c00047a0f000572ee0005fc790006d1610007a8880008af160009b302000aaf52000b8a24000c4238000d2977000dfc75000e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
