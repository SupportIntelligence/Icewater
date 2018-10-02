
rule j26d4_22b1e6cb9e70d115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26d4.22b1e6cb9e70d115"
     cluster="j26d4.22b1e6cb9e70d115"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor malicious genx"
     md5_hashes="['604a7858981bdd95e99d086cc31f0e8c059ece96','fd72e627a044b3a4f2149a705ae85bf7de3f1c20','d46c55874f84b9f9fde90e378c392014e3eb436d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26d4.22b1e6cb9e70d115"

   strings:
      $hex_string = { 5257bf2d92e63233c75f5ac380558bec81c458feffffe8e72000008945f8c7855cfeffff000000000f31d1c0663ded137302ebf40fb7c050a3301301108ad4c1 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
