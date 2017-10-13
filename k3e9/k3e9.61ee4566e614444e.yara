import "hash"

rule k3e9_61ee4566e614444e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.61ee4566e614444e"
     cluster="k3e9.61ee4566e614444e"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d673bbafdef40351130a82152ffe2a61', 'd69ea5807a270e0eb44b0457d98dffbe', 'd673bbafdef40351130a82152ffe2a61']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

