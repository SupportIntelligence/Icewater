
rule m3e9_11915366cb1b9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.11915366cb1b9912"
     cluster="m3e9.11915366cb1b9912"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar scudy zusy"
     md5_hashes="['212fbdc5ca1c593108d1e6c7b9f9637c','46a428ec314afcd650678a0b894842d7','eb5f5586aff314e152d7e9a1aa53c0bc']"

   strings:
      $hex_string = { c751fc633cd02b5c2f809c1000afad760136a749c618e065bb8cc01e42f52e2092cff3db5ff9f2d53f503e0afd892224403964f7910713b47f1922795ba37260 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
