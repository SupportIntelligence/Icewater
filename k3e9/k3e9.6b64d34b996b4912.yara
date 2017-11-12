import "hash"

rule k3e9_6b64d34b996b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b996b4912"
     cluster="k3e9.6b64d34b996b4912"
     cluster_size="45 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['ab08c563025629012be1dd911fb89106', 'b98ac735d595bcd8b30b253249876136', 'b0c8e618a0fe6af9495a568c775356e9']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(11360,1036) == "344675ffeadac8a29fb9e31d1c7725a6"
}

