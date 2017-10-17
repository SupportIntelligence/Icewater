import "hash"

rule m3e9_49166d8ccbe96912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.49166d8ccbe96912"
     cluster="m3e9.49166d8ccbe96912"
     cluster_size="51032 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bladabindi backdoor starter"
     md5_hashes="['004440e1f99dd1490068c5b917a7e0cd', '0157fb040dc10d30b350348a828b65a3', '008315221e0ea237c9d89ba95dec8b07']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(98304,1024) == "709e14882c3b694fb75b7cb558e53f7e"
}

