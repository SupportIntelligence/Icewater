
rule n26bb_3a4c6b1879652ef2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.3a4c6b1879652ef2"
     cluster="n26bb.3a4c6b1879652ef2"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="autoit malicious asvcs"
     md5_hashes="['3348d281c96cfc95ed2c3279d9cf62668aa717c6','6731f85272d5ec5406851d077a2b6599dc9ef8a1','4f96b1971920c86f8ef233524d6b0fd350ea4f6c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.3a4c6b1879652ef2"

   strings:
      $hex_string = { d1f8880c103bf77cc0b0015e5f5b8be55dc332c0ebf5558bec515356578bf98bf257e894d3fbff8326005933c9c745fc30000000418d50ff33db85d2783f0fb7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
