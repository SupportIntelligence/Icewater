
rule m2321_12966a5056ae4aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.12966a5056ae4aba"
     cluster="m2321.12966a5056ae4aba"
     cluster_size="213"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos hiddenapp boosad"
     md5_hashes="['05fcec56574818038b00246de430039c','0817f5c5fbc8b262a0db28dd1685ef67','161775079b4c9f42532cfa77374e7607']"

   strings:
      $hex_string = { 0fe4e11714c0aabdb8f0075e27523184e553290168d4239256f4d82c6d337c7ae2c35a096c9e423df97270c78b4680d5692af5d7d9df393f04eba76ad6639f16 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
