
rule m2321_5b994590dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5b994590dee30912"
     cluster="m2321.5b994590dee30912"
     cluster_size="4"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['18940d68b687f945eb54d71783c0d145','af7f94b686e026fab72897433f216b80','fa6222ac187fc71f85acba33bd437119']"

   strings:
      $hex_string = { 94c2ca70783323a34f483dd3f5e96fb27c65c689edff76051f11e7d0f8b71d8e0d1f914d7fe58ce2122d9695b35cdae07a28cf3977473655840934fbaf9af2d9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
