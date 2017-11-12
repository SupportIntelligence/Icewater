import "hash"

rule m3e9_0cb1b206dd4ad932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0cb1b206dd4ad932"
     cluster="m3e9.0cb1b206dd4ad932"
     cluster_size="497 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy buterat zbot"
     md5_hashes="['9f04c46081d1291531a76f379efaf233', 'a265821e2855022eda2aa00fcbf15e95', '1d2f328749898826cdc23c9e06bdf2c2']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(188288,1088) == "2c02cbeea06d6eafb3a264ee1b01f757"
}

