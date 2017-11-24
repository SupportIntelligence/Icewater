
rule i445_21206e8148001112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.21206e8148001112"
     cluster="i445.21206e8148001112"
     cluster_size="4"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jenxcus autorun dinihou"
     md5_hashes="['18150acc49384014df3bbe364857de70','3a8c726611ae28b92985d773d9d8ab8d','f64a992a14911b30a9bf317c0c99d374']"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c000000000000000000000000000000000000003c0031000000000000000000100057494e444f5753 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
