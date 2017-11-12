import "hash"

rule m3e9_49166d8ccbe96912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.49166d8ccbe96912"
     cluster="m3e9.49166d8ccbe96912"
     cluster_size="51777 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bladabindi backdoor starter"
     md5_hashes="['0102b7428b09b69901a86532a80b41f8', '00f12ab3692b732937b033e85d2ce3ae', '0008d04799018aea8e853ebeba5a69f3']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(98304,1024) == "709e14882c3b694fb75b7cb558e53f7e"
}

