
rule j26f3_435ab509be210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26f3.435ab509be210b12"
     cluster="j26f3.435ab509be210b12"
     cluster_size="316"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family=""
     md5_hashes="['aba9e2559d26edf9895d510b3eade121ffe0119e','7bb418726e8e76146296f3235bf684de016b9ac7','a4489c4ae09677715991c419501263c555bad0ed']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26f3.435ab509be210b12"

   strings:
      $hex_string = { 641f000180b500028d2f0003862c00047a0f000572ee0005fc790006d1610007a8880008af160009b302000aaf52000b8a24000c4238000d2977000dfc75000e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
