
rule n26d5_0d9f6848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.0d9f6848c0000b12"
     cluster="n26d5.0d9f6848c0000b12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['d8787dec99d6f05b5038650d2f4dc37ae34dd58a','82bf82f0b6f264faa5839a0b716e78ddfc792422','d4092b97ad4ac615abe61c9eb190d51590e4dce8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.0d9f6848c0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
