import "hash"

rule m3e9_31856a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31856a48c0000b12"
     cluster="m3e9.31856a48c0000b12"
     cluster_size="43 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['88c343974e6f802e5e69f40e866d9030', '8dd0f17d37aab1d4fa8d408b21e078ea', 'e2f6c7db057f24038958565fde020509']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

