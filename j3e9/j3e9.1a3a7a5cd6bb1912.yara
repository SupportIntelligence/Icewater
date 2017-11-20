
rule j3e9_1a3a7a5cd6bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.1a3a7a5cd6bb1912"
     cluster="j3e9.1a3a7a5cd6bb1912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="spyeyes upatre generickd"
     md5_hashes="['1a5f01413660829564a54600b0d3a8c9','6ab92ffc58f32c06cc8b2454a092f8e0','d85b73b799d6a8f793755b5e38d374d9']"

   strings:
      $hex_string = { a824f017f48f904b84965e7fef2b4237d439129d751572f762cc84189fb6a63aec4dcf40c8a0855b4ce77a803b6388c828a7b3f2e0347968e597f68b215d7243 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
