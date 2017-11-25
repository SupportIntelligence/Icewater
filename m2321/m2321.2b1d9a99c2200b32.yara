
rule m2321_2b1d9a99c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b1d9a99c2200b32"
     cluster="m2321.2b1d9a99c2200b32"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['18ebe18ce5684e3eedd9d3f23ee2fd3d','5a3dbf90d8287a6ecfb2c3f55e7ebd98','fdcc941c8fcf021cc65b7e5573022f90']"

   strings:
      $hex_string = { b25c370ec46800f5c049380f1df37eeea244dcc6b3d6d37083c5ef52648743183a1e4fec79063e24f27211c73515f67720286302b7e2cfdc0b3f01e7ff5e1ba5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
