
rule m3e9_1699509242794a9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1699509242794a9a"
     cluster="m3e9.1699509242794a9a"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['012a004871189c0b7c231aaad686db4c','29014cf1644f948d02ffbc4aea6db30a','b8b15021458bc2309e43f9a93173528b']"

   strings:
      $hex_string = { bbe8e441a37d7749c99016d139e33d2bb76e033ba45c50730555b84ad9be8783e54bfb6995236d98027e256f275d99deb1f8a097aeb294eb3cda6a099154d09d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
