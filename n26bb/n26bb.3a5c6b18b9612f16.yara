
rule n26bb_3a5c6b18b9612f16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.3a5c6b18b9612f16"
     cluster="n26bb.3a5c6b18b9612f16"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious asvcs engine"
     md5_hashes="['9c1816c73de089b18392de50209b05c78cbad844','b1e77d7ecffae8356089f2c1c9422ae02b0fbb36','62f0f431328e0857225464f0a183d810d8e13a98']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.3a5c6b18b9612f16"

   strings:
      $hex_string = { d1f8880c103bf77cc0b0015e5f5b8be55dc332c0ebf5558bec515356578bf98bf257e8cfd4fbff8326005933c9c745fc30000000418d50ff33db85d2783f0fb7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
