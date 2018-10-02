
rule o26c9_419d12d1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c9.419d12d1cc000b12"
     cluster="o26c9.419d12d1cc000b12"
     cluster_size="38"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious unsafe gamehack"
     md5_hashes="['6464beaaa120a763a8bce107f4c05b7c7f00b54a','806c8949284c49efb8c5cf7dfceeae2532a80d67','0a8c227675e8743860d68bca2412710c939cb6aa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c9.419d12d1cc000b12"

   strings:
      $hex_string = { 44ba699380c21928431806839529860442dc11c070130d55775da73e419a7ebd98259e5330b1221f65e4e56d2cae6292f472ac904f01978dd558b85ad166f0c1 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
