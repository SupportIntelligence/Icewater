
rule m3f1_11997949c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f1.11997949c4000b12"
     cluster="m3f1.11997949c4000b12"
     cluster_size="96"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos appad triada"
     md5_hashes="['06e9b36dcb09d66816c8441e2743cebb','08d2cb34924ef2c7bcd0f6e432861613','272b04c13e4318e2140c93216ad3b012']"

   strings:
      $hex_string = { d160fa1f811a2d658f716907789dd0a3241e5e178c479a0d94239746f0764ed626f4feb586aff71fdd45ef9f73b6c1ea10352b28ded2bb01a5c440cdbc9ea436 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
