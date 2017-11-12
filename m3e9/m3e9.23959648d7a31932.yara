import "hash"

rule m3e9_23959648d7a31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.23959648d7a31932"
     cluster="m3e9.23959648d7a31932"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ckef delf malicious"
     md5_hashes="['cd8babbc73c5d80a82190d6043441c2b', '85f4013f746f8644d28f4226a99f9e10', '140190888f9a36f0b9cd6fe7bc32f172']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(32892,1028) == "612594d0e3770f02d0893cb782e36b0a"
}

