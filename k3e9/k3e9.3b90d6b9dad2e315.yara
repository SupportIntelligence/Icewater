import "hash"

rule k3e9_3b90d6b9dad2e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b90d6b9dad2e315"
     cluster="k3e9.3b90d6b9dad2e315"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['033bbc2e47d9e2e01ecfbadf4501e8f3', '9d503a3bcb7ac2a2b072482201901774', 'b8604b3b45b9cd3e6cabfd11e6dfb3da']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(1024,1195) == "85494117da9d5bcf1e5f49bc29469b49"
}

