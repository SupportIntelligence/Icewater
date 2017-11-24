
rule m2318_2b39200ad7830932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.2b39200ad7830932"
     cluster="m2318.2b39200ad7830932"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['089ef901e834dd965b36d2ef3c9a6c9e','46cf53c40e578e3f705fdaef08807da9','ef591acc788dca36d004f8e2ec2dcaa4']"

   strings:
      $hex_string = { 687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e64204966 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
