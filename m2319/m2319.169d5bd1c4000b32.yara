
rule m2319_169d5bd1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.169d5bd1c4000b32"
     cluster="m2319.169d5bd1c4000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer coinhive miner"
     md5_hashes="['0d5e6e794507a87a13c10b4f7d01f3d60a37e031','cc3ae30d7eee41a85b3628dfa171443fc97764e2','6b0b885d5dab6afa624347551dda6794a5e2a0c6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.169d5bd1c4000b32"

   strings:
      $hex_string = { 6e7075745b747970653d227375626d6974225d207b77696474683a313030253b7d0a2f2a20332e342e302e32204652414d45574f524b202d206c696e6b426f78 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
