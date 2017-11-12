import "hash"

rule k3e9_7b90d6b8daa2e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.7b90d6b8daa2e315"
     cluster="k3e9.7b90d6b8daa2e315"
     cluster_size="26 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['d72c41180a88b2c51834457ea20e664b', 'a5e4cabe8a8998915c7490c9a3f91f5f', '173b25e621179f22fa1d53c74160a3b7']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(9216,1024) == "876e9a845e43150f15186ffda01fff89"
}

