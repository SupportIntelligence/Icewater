import "hash"

rule k3e9_261dea48c0010b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.261dea48c0010b14"
     cluster="k3e9.261dea48c0010b14"
     cluster_size="539 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre waski generickd"
     md5_hashes="['a70f3c582a0af7ae5983fa5fd5e33bbb', '6098f31b372c05ad55daccb7d8d97137', '56cbd5147b76e7bfe8ef612a2455f838']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9728,1024) == "75a2d0899a122592a16aff5f48078bfc"
}

