
rule nfc8_611c96b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.611c96b9caa00b12"
     cluster="nfc8.611c96b9caa00b12"
     cluster_size="651"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="obfus banker androidos"
     md5_hashes="['362d65afff838fa8a66837945a11bedd93e16f2b','d3ef79da836b4a43bfa091adc3ded597bc4b232e','7ae988c1ba957b8cf70a941c163a8c35964309ae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.611c96b9caa00b12"

   strings:
      $hex_string = { e2f67ce1051e5815c2cc9b3c06fa199e3d77eeeee3705fcfdad3c18e417b3bddbcc3e7dbf1cb8a01c587404fd40ff07e5dbeebfd86ab27b29f531c6b6fcda0f3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
