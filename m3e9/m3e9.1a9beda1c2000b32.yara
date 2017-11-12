
rule m3e9_1a9beda1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1a9beda1c2000b32"
     cluster="m3e9.1a9beda1c2000b32"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer fixflo"
     md5_hashes="['5703cced60e75616f1ead6909843478e','68f6e18d03b85d264ff2f8ea7340e84e','e519acb5545697c88d2d71f625cae23d']"

   strings:
      $hex_string = { e75fcd9f756fcd2176d05b8bc1d4dfd541ce11cc81dcd538eda3bf81e83a93b58e8910ae7a72a018d9e1ec6a4e97d0c072b3c6ad83c495a9a335e810f22f8309 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
