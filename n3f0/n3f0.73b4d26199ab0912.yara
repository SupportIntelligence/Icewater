import "hash"

rule n3f0_73b4d26199ab0912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.73b4d26199ab0912"
     cluster="n3f0.73b4d26199ab0912"
     cluster_size="1044 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious highconfidence amonetize"
     md5_hashes="['2e95990bd27905b5eddd2033352d803e', '38e663afd87d13558fe7c532110bdb16', '3b0c1a93d19fefbff3b490a0e4aef951']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(698824,1080) == "70178f87ae9ba0a06e7e4aa3aa0bec5a"
}

