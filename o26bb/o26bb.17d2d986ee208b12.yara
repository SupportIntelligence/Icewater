
rule o26bb_17d2d986ee208b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.17d2d986ee208b12"
     cluster="o26bb.17d2d986ee208b12"
     cluster_size="186"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious unsafe unwanted"
     md5_hashes="['3d7fcaeb50922adfb8cfb01e103b189cdc20c08b','1a9b61de3fdd9e4c3a6b2c31e152a26e9c218d94','ce14f4597fe7eb59d43cf9c1281031f32c374c6d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.17d2d986ee208b12"

   strings:
      $hex_string = { 44ba699380c21928431806839529860442dc11c070130d55775da73e419a7ebd98259e5330b1221f65e4e56d2cae6292f472ac904f01978dd558b85ad166f0c1 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
