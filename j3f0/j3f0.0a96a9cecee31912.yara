
rule j3f0_0a96a9cecee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.0a96a9cecee31912"
     cluster="j3f0.0a96a9cecee31912"
     cluster_size="123"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious malob"
     md5_hashes="['03a3423d74a6ea21caa3ae3a1bbff593','04ed7f299302f1fc28e7bb6b08595dfe','18d64188cd7cfe0393ec57ae327b2b71']"

   strings:
      $hex_string = { 70356195b6b527fb0f6a5d640cb645f0d3c0f66d0b5202ee3c04264109430f80a240916decf6ed46060630a412462774d5d82d006cff760a50a15844420265db }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
