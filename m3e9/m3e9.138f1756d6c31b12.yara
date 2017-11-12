import "hash"

rule m3e9_138f1756d6c31b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.138f1756d6c31b12"
     cluster="m3e9.138f1756d6c31b12"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['67913b41926694120024c31777171009', '67913b41926694120024c31777171009', '67913b41926694120024c31777171009']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(31744,1024) == "3185a34f2923f1fa768e250be9ebd99c"
}

