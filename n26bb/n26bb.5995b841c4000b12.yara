
rule n26bb_5995b841c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.5995b841c4000b12"
     cluster="n26bb.5995b841c4000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kazy loadmoney cryptor"
     md5_hashes="['6ac234bb3057b198046e37059dc62749e9f7e67a','3d41e9a35ba1add63e0b952c29bdb12bca520420','7f579394ebee45015abd0ba2f13868d39e62cf98']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.5995b841c4000b12"

   strings:
      $hex_string = { 094f4db94e96116a3e000c0053ff8bcff09d2a20ab834622924c6d4b19e8367c24089f008389072e7a05767ff094339e1d90562739cd0038f47e4eb4d8d417d2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
