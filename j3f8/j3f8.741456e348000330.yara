
rule j3f8_741456e348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.741456e348000330"
     cluster="j3f8.741456e348000330"
     cluster_size="4"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['06a6c869234f64e96988abd1d0f38ab4','2d63fcc4e08f022edc0db0bc64ae00cf','e5d4b923ee1d00397000a65195d4fd29']"

   strings:
      $hex_string = { 2f436f6c6c656374696f6e3b00144c6a6176612f7574696c2f4974657261746f723b000f4c6a6176612f7574696c2f4d61703b0004545950450001560002564c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
