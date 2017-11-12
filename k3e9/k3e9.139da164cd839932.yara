import "hash"

rule k3e9_139da164cd839932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164cd839932"
     cluster="k3e9.139da164cd839932"
     cluster_size="1380 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a529f1e6f4a0405e78bdcf8a1683d2b2', '714eea4d484991f858eec53b7bb9ab3a', '99a49ae23f0c713b7a923b92897e0815']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

