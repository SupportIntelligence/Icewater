import "hash"

rule k3e9_0916f3a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0916f3a9c8000932"
     cluster="k3e9.0916f3a9c8000932"
     cluster_size="72 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor injector"
     md5_hashes="['b39a4aa63b2c36befefb174929f1e3c7', 'ae77610709eacfad0eabfcb6a2b61edc', 'bb525076c7317a6fc68f7cc902096f51']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

