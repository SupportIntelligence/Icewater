
rule n231d_099c90b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.099c90b9c2200b12"
     cluster="n231d.099c90b9c2200b12"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hqwar bankbot"
     md5_hashes="['d13df2faee707e88601a3f13116b00a6a1c386d6','a7f7249c0c6cf900487d959217b7af480b9cd122','5d208b06d1cfb462cde0ff989cd9b683ebbf97da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.099c90b9c2200b12"

   strings:
      $hex_string = { dbb4415ddfec9ac1f0b8364572507f58f1ccd31814880130b2d271160b6a193f8978eaa17374104742cfa5981fff99032046ab0943ad23d6c9957a84e29b656f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
