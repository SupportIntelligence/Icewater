
rule k2321_499a9a72dbbb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.499a9a72dbbb0b32"
     cluster="k2321.499a9a72dbbb0b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ganelp autorun backdoor"
     md5_hashes="['2b26f91701e27e35e8b29d622f173e88','69552207df2deaeeae5d68b76da7f687','d436e4524ddf371192b0ef82fa9178a6']"

   strings:
      $hex_string = { 8797382816a7dcbcf16c250515532c2b5a4d929b11123a203f4f934b1c35c6d0ec6dfe5870bdd8096723b3a841375de57448add64afbf3a3d4bbc850c55224ee }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
