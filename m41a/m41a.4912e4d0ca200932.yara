
rule m41a_4912e4d0ca200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m41a.4912e4d0ca200932"
     cluster="m41a.4912e4d0ca200932"
     cluster_size="1743"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious mgjun moderate"
     md5_hashes="['79bd298b51ac6d0b0f9f844ebc833d8c699e99ca','40508a041231ca9b3d5b10c5ea1b254c5e6d8aaa','d9c4d1dd443aed1283919be7efc52d978ff989f9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m41a.4912e4d0ca200932"

   strings:
      $hex_string = { 74304883c9ff33c0498bf966f2af488d15b20c0100458bc448f7d18d0409488bcb89442420e855bbffff85c00f88b705000044393556b5010075394c8b0d4d9f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
