import "hash"

rule m3e9_61189cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61189cc9cc000b12"
     cluster="m3e9.61189cc9cc000b12"
     cluster_size="113 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171018"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['7bafebe6acd89b2611ecd821558f8fe5', 'b73083351d077d4115cdedcb9c43ed3a', 'be37b9e0fee9edc3e6daac4b44cc3d1d']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(59904,1024) == "f24215dac73f1ce5241359766ff64685"
}

