
rule j3f0_279525671cc30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.279525671cc30b12"
     cluster="j3f0.279525671cc30b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious malob"
     md5_hashes="['0acd0e4c6df41dd367fd67f3d9fa3552','3eedcc2ff4630118f66fa4e58612c502','b91b909f5f8d593caa3d221262b25bc3']"

   strings:
      $hex_string = { 70356195b6b527fb0f6a5d640cb645f0d3c0f66d0b5202ee3c04264109430f80a240916decf6ed46060630a412462774d5d82d006cff760a50a15844420265db }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
