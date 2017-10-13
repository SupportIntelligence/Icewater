import "hash"

rule m3e9_611c8d9c4ee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c8d9c4ee30912"
     cluster="m3e9.611c8d9c4ee30912"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef diple"
     md5_hashes="['81c8d2b5650fe66d55ffbae63ca3c5a2', 'b8dfa8840b60e0dc844921f993d62c92', 'a438e6f36a03a5557094a97035f4c8a5']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(50176,1024) == "463de20334f42250e80cb292d3be7316"
}

