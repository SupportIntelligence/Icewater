
rule o26bb_57d3530cca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.57d3530cca200b12"
     cluster="o26bb.57d3530cca200b12"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gamehack malicious unsafe"
     md5_hashes="['ee3e225ce176ae6f01cd0e62375bcd641349aeb7','5ea1e0e57b6998ccdebd2fab9c71f40c543b69ce','1d96f9604b41e876eeabd7f12a1edd971de5db59']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.57d3530cca200b12"

   strings:
      $hex_string = { 44ba699380c21928431806839529860442dc11c070130d55775da73e419a7ebd98259e5330b1221f65e4e56d2cae6292f472ac904f01978dd558b85ad166f0c1 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
