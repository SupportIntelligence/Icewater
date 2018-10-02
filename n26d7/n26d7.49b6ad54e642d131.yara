
rule n26d7_49b6ad54e642d131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.49b6ad54e642d131"
     cluster="n26d7.49b6ad54e642d131"
     cluster_size="2929"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious susp unsafe"
     md5_hashes="['4e0457feef46cb5cd61755b0e9633fdb4547c329','7fb0e4a9fbc0ec3d65bef29915dc9b19ed33abd1','aa1f420bdd17a5f1f4a18bdf2b374d78327cdee8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.49b6ad54e642d131"

   strings:
      $hex_string = { 575051525356e8a2caffff83c42885c074b35f5e5b8be55dc38bd03bc17d313b776c73100fb6063945fc742442463bd17cedeb1c837f7c0074163b77787611b8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
