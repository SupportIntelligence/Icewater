import "hash"

rule k3e9_232cae2593eb9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.232cae2593eb9932"
     cluster="k3e9.232cae2593eb9932"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="berbew qukart backdoor"
     md5_hashes="['b9d8bd9d6777ec29fa561d469b8cd105', 'b9d8bd9d6777ec29fa561d469b8cd105', '5d9fef02d503adfaffe57e261904e9ed']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

