import "hash"

rule k3e9_031ca619da9ad115
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.031ca619da9ad115"
     cluster="k3e9.031ca619da9ad115"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qukart backdoor berbew"
     md5_hashes="['2fe6d968f4134986d64ff3584160f3b5', '2fe6d968f4134986d64ff3584160f3b5', '2fe6d968f4134986d64ff3584160f3b5']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(49603,1249) == "d06857e133fd37b7cc5535176ea36368"
}

