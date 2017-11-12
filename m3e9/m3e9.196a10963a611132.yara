import "hash"

rule m3e9_196a10963a611132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.196a10963a611132"
     cluster="m3e9.196a10963a611132"
     cluster_size="130 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus jorik wbna"
     md5_hashes="['ce7db05c7f758bbfa96b36cef2309c67', 'b2857ba56025771e4228e0991c6be2e2', 'd9235cb758dce39537e3bfdb7f9202cf']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(132096,1024) == "c257c18d74bd919b981ccc18268ad346"
}

