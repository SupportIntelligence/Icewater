import "hash"

rule m3e9_1918bb29c8800912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1918bb29c8800912"
     cluster="m3e9.1918bb29c8800912"
     cluster_size="4227 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="browsefox riskware adplugin"
     md5_hashes="['03b7d1e7d704f405caab6db02f1928e5', '0b2edea79041d63c3c0d111acbdb72bf', '281f5db0721144dd4e9c18d9b67f39c5']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(96768,1024) == "1fbda6246048c36f833f0380b13011b2"
}

