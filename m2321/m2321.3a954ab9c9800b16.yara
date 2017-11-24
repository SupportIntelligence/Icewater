
rule m2321_3a954ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3a954ab9c9800b16"
     cluster="m2321.3a954ab9c9800b16"
     cluster_size="28"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['1471e60c11ffe7dc49c62d46f9783d7c','21361877d1c1c300f9297a9d835ef815','a9a5805d1c7cd52a7e0e2fd6b7112aec']"

   strings:
      $hex_string = { a7bba1a62e1871fab53d2d0a3ce251caf3421e0f644ab9d4e32f0c47d4724524a436d1b628f586238a56b1dfad1cdb9b22d3146cb7f7919ac6e9f9dab665cb1a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
