
rule m3e9_6cc4159da3346f86
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6cc4159da3346f86"
     cluster="m3e9.6cc4159da3346f86"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky vbkrypt"
     md5_hashes="['085c650cb07a8b6ae361fb4fc3280b8a','38ef9903c67d5a2431d47c1415f2d0c4','d5d95e05795e6cd41709d7bf051e1c27']"

   strings:
      $hex_string = { eaebe8edaaa9a8a6a094141a181f77c6dce0e0e0e1f6e0dcf3d13f1f0000000000001f052d7f6f6f6f81d0f0f8f8f8f8f7f7effaecebeda5a89e9495221638bc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
