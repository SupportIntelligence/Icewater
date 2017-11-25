
rule m3e9_3b07eda1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3b07eda1c2000b32"
     cluster="m3e9.3b07eda1c2000b32"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer malicious"
     md5_hashes="['2416e6c65d6e736fb22f87edee758b61','5702c77cf2184ff72c271e1bc359f53b','f6f76556e4b4aa726c588ce2b8004970']"

   strings:
      $hex_string = { a29550090531c1c83cf76219d7d9c55dbbbeabd5c9c625a0e16ee0dbd69d5ffe5c136f3fb4aebac7902d559029f3494634354f882942d21cb5564841e9d044f5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
