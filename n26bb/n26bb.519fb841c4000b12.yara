
rule n26bb_519fb841c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.519fb841c4000b12"
     cluster="n26bb.519fb841c4000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kazy loadmoney cryptor"
     md5_hashes="['affeee8df09b05682f04c821566888c0ddef66b0','7eab15c3bd9456c61dd2b0065ce614bcafe07da7','90a373bf12686867d651de1d53d1c27b8eed7e3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.519fb841c4000b12"

   strings:
      $hex_string = { 094f4db94e96116a3e000c0053ff8bcff09d2a20ab834622924c6d4b19e8367c24089f008389072e7a05767ff094339e1d90562739cd0038f47e4eb4d8d417d2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
