import "hash"

rule k3e9_3b90d6b8dab2e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b90d6b8dab2e315"
     cluster="k3e9.3b90d6b8dab2e315"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['27a9fc6403b9225803e2342cedba2884', 'cacfc3df90b103a42f078890148f44bb', '371f3570d28a1c34bf91a6a3b5705532']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(18432,1024) == "d6ae07042c3d344b982cb960de27b396"
}

