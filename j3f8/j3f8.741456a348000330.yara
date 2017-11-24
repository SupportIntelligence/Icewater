
rule j3f8_741456a348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.741456a348000330"
     cluster="j3f8.741456a348000330"
     cluster_size="7"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['12a4856ac3cca82d5d332651d47e7f83','1968a16506c4dc4968a77d5a2c0b4417','d2bd7edca4d36949b9eaf466aa599b1c']"

   strings:
      $hex_string = { 2f436f6c6c656374696f6e3b00144c6a6176612f7574696c2f4974657261746f723b000f4c6a6176612f7574696c2f4d61703b0004545950450001560002564c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
