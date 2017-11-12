import "hash"

rule k3e9_63146ef11c92fb16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ef11c92fb16"
     cluster="k3e9.63146ef11c92fb16"
     cluster_size="34 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ab201e6c774973983e5d506facaa3591', 'd4d065e3a8c0a82b8184c756133be560', '0a0cb13f511466b9a290d2f2b0e34e87']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(11264,1024) == "0ba0e2ff26eff80ce27be3a7f3b091a4"
}

