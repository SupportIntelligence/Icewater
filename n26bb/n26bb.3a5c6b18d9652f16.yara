
rule n26bb_3a5c6b18d9652f16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.3a5c6b18d9652f16"
     cluster="n26bb.3a5c6b18d9652f16"
     cluster_size="60"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="asvcs engine heuristic"
     md5_hashes="['a6c0f8a8f394c23a1d24104a51a912c585225c71','5930b8cb0e0e3154bef7f292749ea12e4a877ce9','c3a6c0044395b8f7ec924a44a03b6b5f831faf3a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.3a5c6b18d9652f16"

   strings:
      $hex_string = { d1f8880c103bf77cc0b0015e5f5b8be55dc332c0ebf5558bec515356578bf98bf257e894d3fbff8326005933c9c745fc30000000418d50ff33db85d2783f0fb7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
