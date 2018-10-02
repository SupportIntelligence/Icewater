
rule p26bb_639e11e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.639e11e9c8800b12"
     cluster="p26bb.639e11e9c8800b12"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="attribute crack engine"
     md5_hashes="['03975174232f802df427617e85d332ee9dcc5f33','7fd74046ed77bc5da52997a9afc16a470b46128b','bbbc48f2aaf09c56e6bec05292ad28e8396a0bb2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.639e11e9c8800b12"

   strings:
      $hex_string = { 44ba699380c21928431806839529860442dc11c070130d55775da73e419a7ebd98259e5330b1221f65e4e56d2cae6292f472ac904f01978dd558b85ad166f0c1 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
