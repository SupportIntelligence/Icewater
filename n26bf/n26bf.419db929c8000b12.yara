
rule n26bf_419db929c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.419db929c8000b12"
     cluster="n26bf.419db929c8000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious nanocore backdoor"
     md5_hashes="['7ce9fbb43e37dfa8ec1d9188985ed69a3af4d1f3','291abb4018a086e7024ad7bb08fbb445fc14f5fe','f32dac4b400cb1c900106350b5556aac16232ac9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.419db929c8000b12"

   strings:
      $hex_string = { 0d8c0500001b2d032b072a2b0b2a022bf0280100002b2bf2022bf213300200180000000a0000112b101200fe150500001b2b09810500001b2a032bed062bf41e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
