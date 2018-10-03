
rule o26bb_4b163949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4b163949c8000b12"
     cluster="o26bb.4b163949c8000b12"
     cluster_size="2306"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="midie diskwriter crypt"
     md5_hashes="['7223de76753ea30fa8967fcba95670106d766d73','e6e2131ff233fd20e58eaffc4485043d3baf91b0','4ebea2b6159b5c1664ef56cae58090223825bf5b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4b163949c8000b12"

   strings:
      $hex_string = { c1fb0581e51f0000805779054d83cde0458b742414395e047f3f8d7b013b7e087f048bc6eb0a5756e809fcffff83c40885c075055f5e5d5bc38b46043bc77d16 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
