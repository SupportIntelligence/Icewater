
rule k2319_185396b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185396b9ca800b12"
     cluster="k2319.185396b9ca800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik czyf diplugem"
     md5_hashes="['10e72c4a6b53f3e760d350dc1a962187e14cc70b','6c73a39d0bbcc224a1209bc8a27f4a495b5a24fb','6b507d1d59fb348a2718a86a5c19cd3f9b9993cb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185396b9ca800b12"

   strings:
      $hex_string = { 415b4b5d213d3d756e646566696e6564297b72657475726e20415b4b5d3b7d766172204c3d283078343c283132332c3630293f28352e393545322c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
