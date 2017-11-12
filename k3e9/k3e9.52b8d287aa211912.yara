import "hash"

rule k3e9_52b8d287aa211912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52b8d287aa211912"
     cluster="k3e9.52b8d287aa211912"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['6e06fc5eca36a1d2da065f8fd918636c', '9ea3f1beb769acdd269070d68b586d61', '1ba3f991ed316ef78766a915cfada47c']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(9560,1066) == "41225ea7cd7bc5ea699676982c5b42ce"
}

