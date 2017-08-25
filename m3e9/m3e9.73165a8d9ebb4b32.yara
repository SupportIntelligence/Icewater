import "hash"

rule m3e9_73165a8d9ebb4b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73165a8d9ebb4b32"
     cluster="m3e9.73165a8d9ebb4b32"
     cluster_size="420 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="swisyn bner mofksys"
     md5_hashes="['57b131f609838de8aa843a1c5c95b4b2', '25eb5edc581bcf8d4a5ee2ab6cb3c79e', '865fc15abbf0b50cf25623c5ef2ac519']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(150528,1024) == "446877bb72cb1aac8e4408f2cd169793"
}

