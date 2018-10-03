
rule n231d_519a94e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.519a94e9c8800b32"
     cluster="n231d.519a94e9c8800b32"
     cluster_size="2951"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos dldr andr"
     md5_hashes="['6ac79306306d5cc848d37dd3e5d0cd3a75deaf65','6bd1df94beefa54e9969661e18a3a9d191f105d9','cf328d4dbe8b60b75d53ac936e9ff193a42d7b7e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.519a94e9c8800b32"

   strings:
      $hex_string = { da6db6889474278ce0deef86d5dd26a7f4d1673f7cf6e2e3ffe97ffc1f52b99dc5d004315553238418385b1532365eca7ed34381d9ac3b3e3c6ce6ed2e0dabcd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
