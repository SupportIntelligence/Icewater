import "hash"

rule k3e9_69b1a166cda39b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69b1a166cda39b12"
     cluster="k3e9.69b1a166cda39b12"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['7753d4fcf25e2f4c9e31964c13e88710', '87b81a834d254038913bfec4beec0e7f', 'a94437f7f253324f41d8d4f2d0ca3d09']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(15360,1024) == "f751fc03ac106c581a7746569740097e"
}

