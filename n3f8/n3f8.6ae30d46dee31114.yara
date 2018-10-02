
rule n3f8_6ae30d46dee31114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6ae30d46dee31114"
     cluster="n3f8.6ae30d46dee31114"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos smforw smsagent"
     md5_hashes="['3aa0e5678a3ea1a9b453125f952f7498af9b27d6','88251f6d5223fbfa158a927f6cd80f6e1b1df2c7','93820a895f2a56ea8032d19a4248c1eedd722d58']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6ae30d46dee31114"

   strings:
      $hex_string = { 79636f6d624d5232537475623b00023e2800073c54543b3e3b29002e4c616e64726f69642f737570706f72742f76342f766965772f5669657750616765722453 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
