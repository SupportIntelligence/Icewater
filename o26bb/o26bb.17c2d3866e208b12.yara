
rule o26bb_17c2d3866e208b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.17c2d3866e208b12"
     cluster="o26bb.17c2d3866e208b12"
     cluster_size="61"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gamehack malicious unsafe"
     md5_hashes="['7dce6c525ee57cdb423dcbd26b4f4811261a5d58','29d83c3825c912c9fcd00e372c9b88ec5b341246','ddc9dae699562947b705a1e51879af3fa4131bb3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.17c2d3866e208b12"

   strings:
      $hex_string = { 44ba699380c21928431806839529860442dc11c070130d55775da73e419a7ebd98259e5330b1221f65e4e56d2cae6292f472ac904f01978dd558b85ad166f0c1 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
