import "hash"

rule m3e9_73165a8d9ea74b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73165a8d9ea74b32"
     cluster="m3e9.73165a8d9ea74b32"
     cluster_size="397 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="swisyn bner mofksys"
     md5_hashes="['3336f54a5190d0ecb855d42935f83c3e', 'e9f6a645b349bf3a69290ef374a8992b', 'a100dc768e2f3be812e5397d409ff628']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(150528,1024) == "446877bb72cb1aac8e4408f2cd169793"
}

