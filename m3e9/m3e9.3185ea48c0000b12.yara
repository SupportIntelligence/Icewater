import "hash"

rule m3e9_3185ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3185ea48c0000b12"
     cluster="m3e9.3185ea48c0000b12"
     cluster_size="57 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['8e4be33abbea1f89003b5bd713148169', 'ce069928868e8ef0e07aa9c5a987075d', 'b93718053ac9beaa4b65ca100d7754c1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

