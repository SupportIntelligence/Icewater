
rule k3e9_119c9cc9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.119c9cc9cc000b32"
     cluster="k3e9.119c9cc9cc000b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vilsel pworm smck"
     md5_hashes="['097d8ee3bf9de1274e3da17ba87c06bb','1c1636088626de9fe32ce4a9b514c921','a4983ba12e0cfbd012f39294050c1934']"

   strings:
      $hex_string = { 3d33da0059f2d17e2914a39feb316e7e5743a4a9b149d44092afd0509e6eeac54d378769c17cddcdf576b2775e866bbebbf0de263e4be4e55f46cfba793bfe66 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
