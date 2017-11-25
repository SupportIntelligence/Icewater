
rule j3e7_7d14d6e348000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7d14d6e348000110"
     cluster="j3e7.7d14d6e348000110"
     cluster_size="9"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['080b6a34a6b24bfad600da864dedf04d','583bdc1279c00384f3c2f924ccc1c25d','f9b1ea3949bb9f20a505292d9519eb74']"

   strings:
      $hex_string = { 2f436f6c6c656374696f6e3b00144c6a6176612f7574696c2f4974657261746f723b000f4c6a6176612f7574696c2f4d61703b0004545950450001560002564c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
