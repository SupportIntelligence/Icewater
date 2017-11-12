import "hash"

rule k3e9_7b90d6b9daa2e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.7b90d6b9daa2e315"
     cluster="k3e9.7b90d6b9daa2e315"
     cluster_size="62 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['da2ffaacbcf28c62e02a7d4979dd031c', 'd99de900bda71adf5a1c432b137d89ce', 'e720016018f7b0bc3a05608a50a380a5']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(1024,1195) == "85494117da9d5bcf1e5f49bc29469b49"
}

