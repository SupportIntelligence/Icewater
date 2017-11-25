
rule j3e7_7994d6c3c8000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7994d6c3c8000310"
     cluster="j3e7.7994d6c3c8000310"
     cluster_size="641"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['004140fbf2910cc4dd4574eafdeebb3f','00d21ad9e08cf521bf9e82c2a306554a','0798a5bb685403a46468cb38bbbe7f83']"

   strings:
      $hex_string = { 63742f4669656c643b001a4c6a6176612f6c616e672f7265666c6563742f4d6574686f643b00154c6a6176612f7574696c2f41727261794c6973743b00164c6a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
