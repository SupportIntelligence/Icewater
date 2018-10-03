
rule n26bb_1bcac6a793bb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1bcac6a793bb0b32"
     cluster="n26bb.1bcac6a793bb0b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious adwaredealply"
     md5_hashes="['ab49dcf251ed9127e53532913b575ec7c754632d','be16fee978a85df91148cea52e6983a124329cf0','2bb5befd3f134142e67443a623d41d2a0458cce9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1bcac6a793bb0b32"

   strings:
      $hex_string = { 38d974188d7431074f75f28b40dc85c075dc5aeb1b8a1a8a4e06ebe88a5c3106321c1180e3df75ed4975f18b065a01d05f5e5bc352515384d27c03ff50f431d2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
