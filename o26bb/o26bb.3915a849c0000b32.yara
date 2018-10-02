
rule o26bb_3915a849c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.3915a849c0000b32"
     cluster="o26bb.3915a849c0000b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gamehack malicious unsafe"
     md5_hashes="['e3070334dc43a7f176f9f3d24784dc3b2e3795e6','417b177803726325f8ff8b180c1a59dba9a2cf1f','0d72196cede362d1d3d392ecb98239f06c8f31d6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.3915a849c0000b32"

   strings:
      $hex_string = { 00030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
