import "hash"

rule k3e9_1994f3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1994f3a9c8000b16"
     cluster="k3e9.1994f3a9c8000b16"
     cluster_size="17 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor razy injector"
     md5_hashes="['20502a46e6902fd4f1e2f4f387bfe446', 'b97e7c60f5ffd4a68be625302009069e', '20502a46e6902fd4f1e2f4f387bfe446']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

