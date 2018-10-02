
rule n3f8_6ab3ad229ad30914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6ab3ad229ad30914"
     cluster="n3f8.6ab3ad229ad30914"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos smforw smssend"
     md5_hashes="['7e03cb6fab16f63b94d3b7952f5cc209796dc274','b67f8db324cfe2b247f7c7658e1b1978e4e5d3f7','a2a3eb241054fdf5e99e20ae97f96bd64aaf48db']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6ab3ad229ad30914"

   strings:
      $hex_string = { 54cc1f01014d440c0c0d6e203315cb000c0b6e103c150b000c0b7020f814ba007020ba039800075812195c89a3006308fd0038082a001a08fb0222092803079e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
