
rule j3f0_1696a9cecee31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.1696a9cecee31932"
     cluster="j3f0.1696a9cecee31932"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious malob"
     md5_hashes="['038b99fe9acfd349b2bd3055c706dc71','21ceb202d1c7a1fcfd811afc401ffd24','f66775ee8eed2bcfe7d92bab73e7e2f3']"

   strings:
      $hex_string = { 70356195b6b527fb0f6a5d640cb645f0d3c0f66d0b5202ee3c04264109430f80a240916decf6ed46060630a412462774d5d82d006cff760a50a15844420265db }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
