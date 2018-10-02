
rule n26bb_3a9b12e9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.3a9b12e9ca000b32"
     cluster="n26bb.3a9b12e9ca000b32"
     cluster_size="251"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="amigo bacs heuristic"
     md5_hashes="['97d2426e7c2b528a2a45c39108db05efd2f0962c','f3bc44e50427dec94cfc1246aed413b1cddcfddf','9e34abbf648291db412e82a802ee1a1700475339']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.3a9b12e9ca000b32"

   strings:
      $hex_string = { 328038308d5001751c8a023c8275160fb64a010fb64202c1e10883c11303c881e1f8ffff0f85c9740a894f14b001897718eb0232c05e5f5dc20400558bec837d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
