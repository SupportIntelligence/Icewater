
rule m24c4_2b941518dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m24c4.2b941518dee30912"
     cluster="m24c4.2b941518dee30912"
     cluster_size="5"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['2027bb0b1f3cf3e16509757f3ada5b35','86991fa8278880dad3585c80eed6a239','fd22e50f5b76b2458138eb214963c4a9']"

   strings:
      $hex_string = { 8c65078873deaf62634aadc4ddf01066d3702ef874010f4d23cef414fdb17158d7a706b5bea1792df791990003485ceebf6b87704142e8c737eaeb9ea4dfbb9f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
