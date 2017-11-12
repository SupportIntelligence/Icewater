import "hash"

rule k3e9_231ef3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.231ef3a9c8000b12"
     cluster="k3e9.231ef3a9c8000b12"
     cluster_size="28 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor razy injector"
     md5_hashes="['cf3aa73db7a8f684a0ab1cfe4b3ffab6', 'd34c73a58ef54f813e338d104de7a392', 'ac6bc418b24f0ea2182219237ef849d2']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

