import "hash"

rule k3e9_63146ef11c82fb16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ef11c82fb16"
     cluster="k3e9.63146ef11c82fb16"
     cluster_size="17 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c8343fafa3327e0f99ea1e81037c8659', 'c2d0ba2fa802fd3a8a7cd27d4afbb6f9', 'a2179a69119fa63a51bbdf70f133e66b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(11264,1024) == "0ba0e2ff26eff80ce27be3a7f3b091a4"
}

