
rule n3e9_24c9db53850be98e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.24c9db53850be98e"
     cluster="n3e9.24c9db53850be98e"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softonic razy softonicdownloader"
     md5_hashes="['0b3f92262bea65f406837d1a5f22d6c9','121848931d73356fa6831face06d22d7','548499e2eaf9c2a79ea816f14fe31f12']"

   strings:
      $hex_string = { 094cbf3d05dcebf5c6751c00b4f7c64a92fc886d07efbd6ab59a5aadd6c71e238011daedb69e3e7d2aef4726288d6835ca3cb0996efd513fb9b474b3fbecd91f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
