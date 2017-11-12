import "hash"

rule k3e9_52b85287ea210912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52b85287ea210912"
     cluster="k3e9.52b85287ea210912"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['253d76ab42ac46767c82f90cd885e91b', '253d76ab42ac46767c82f90cd885e91b', '04762676a2bf6dc04484e961062364c0']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(9560,1066) == "41225ea7cd7bc5ea699676982c5b42ce"
}

