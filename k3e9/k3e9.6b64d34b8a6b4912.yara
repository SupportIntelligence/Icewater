import "hash"

rule k3e9_6b64d34b8a6b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b8a6b4912"
     cluster="k3e9.6b64d34b8a6b4912"
     cluster_size="113 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['1d7163a8bd7e7912bb4f1dd7a8589532', 'e5ff4e345ea89dd0ab7fbc64761430b1', 'c01bc43a6585ae8668934089c4cfcb31']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(11360,1036) == "344675ffeadac8a29fb9e31d1c7725a6"
}

