
rule m3e9_3919eda1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3919eda1c2000b32"
     cluster="m3e9.3919eda1c2000b32"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer fixflo"
     md5_hashes="['0f190b7b8ac9d3fb2a3d7caad13f0a9a','215b7347a25482a6de3153b09e7796c4','c77094134491601ea63e7c9e2095de84']"

   strings:
      $hex_string = { a29550090531c1c83cf76219d7d9c55dbbbeabd5c9c625a0e16ee0dbd69d5ffe5c136f3fb4aebac7902d559029f3494634354f882942d21cb5564841e9d044f5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
