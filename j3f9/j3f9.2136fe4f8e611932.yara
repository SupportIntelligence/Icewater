
rule j3f9_2136fe4f8e611932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f9.2136fe4f8e611932"
     cluster="j3f9.2136fe4f8e611932"
     cluster_size="4"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious generik"
     md5_hashes="['4b5998afc736877d764a1cdab6aaa9a8','4bfc5f05291a1d495d0f0b0f98075e22','b15c10d575ab8e061d4b890adc3c21ac']"

   strings:
      $hex_string = { e48b4d8403483c8b45f00fb740108d4401188945e88b45912b8550ffffff506a008b4584038550ffffff50e8cf07000083c40c8d45f4506a040fb645886bc028 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
