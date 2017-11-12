import "hash"

rule k3e9_2314a61bc29ad315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2314a61bc29ad315"
     cluster="k3e9.2314a61bc29ad315"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qukart berbew backdoor"
     md5_hashes="['5c6bdf4e0a74ab0971ab3f0a12ae25f6', '5c6bdf4e0a74ab0971ab3f0a12ae25f6', 'b3395a1a04a31018989f98d8c0bd48fa']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(49603,1249) == "d06857e133fd37b7cc5535176ea36368"
}

