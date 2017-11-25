
rule i3ed_07bb33e342249116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.07bb33e342249116"
     cluster="i3ed.07bb33e342249116"
     cluster_size="1091"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue bundpil malicious"
     md5_hashes="['007082580aa358d8b329e1220cf6f83c','010ab7d1ad18cef92f23fdab833385ce','0517ffed04535be2873b3495bad31f43']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a13832001083ee04ebea50ff151c20001083253832001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
