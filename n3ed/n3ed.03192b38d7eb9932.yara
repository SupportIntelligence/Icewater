import "hash"

rule n3ed_03192b38d7eb9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.03192b38d7eb9932"
     cluster="n3ed.03192b38d7eb9932"
     cluster_size="4585 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="elex xadupi riskware"
     md5_hashes="['31feaa0d09520c55a61ecaff10e4d751', '0b3a7507f499151d06f1fe94b60f7656', '018327153ed2dbadeaea1a38f153745d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(739328,1536) == "1baacf8752122169d720c6e2cd09c896"
}

