import "hash"

rule m3e9_73165a8d9ebb4b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73165a8d9ebb4b32"
     cluster="m3e9.73165a8d9ebb4b32"
     cluster_size="498 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="swisyn bner mofksys"
     md5_hashes="['2e6945e3b26bf14ae9ebc2395340d635', '23606b4eebf3f268a3766a01a1b433c9', '4d94fd68e0a8d8b43d06893a41f61d6f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(150528,1024) == "446877bb72cb1aac8e4408f2cd169793"
}

