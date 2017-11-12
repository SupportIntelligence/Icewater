import "hash"

rule m3e9_1c1a9cc1c4000922
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1c1a9cc1c4000922"
     cluster="m3e9.1c1a9cc1c4000922"
     cluster_size="28 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy androm backdoor"
     md5_hashes="['f198d33d1fcb58a2e4a8840e2162fa41', '0d14c69b4529615ab23ee1cc5f7e44e0', '65aac25a2cb8304417877af270154cde']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(20480,1024) == "13d3268c5c0285305299536cda4475aa"
}

