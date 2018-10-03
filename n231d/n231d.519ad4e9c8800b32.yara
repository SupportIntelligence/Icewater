
rule n231d_519ad4e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.519ad4e9c8800b32"
     cluster="n231d.519ad4e9c8800b32"
     cluster_size="2728"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos dldr andr"
     md5_hashes="['9673ecbec8ae641d5e5452f1c500cee3460c4704','68789dc52c050c099160db3792c61afe885dff5c','2814306bb410336d267cb3f78c46c911c6aae680']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.519ad4e9c8800b32"

   strings:
      $hex_string = { da6db6889474278ce0deef86d5dd26a7f4d1673f7cf6e2e3ffe97ffc1f52b99dc5d004315553238418385b1532365eca7ed34381d9ac3b3e3c6ce6ed2e0dabcd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
