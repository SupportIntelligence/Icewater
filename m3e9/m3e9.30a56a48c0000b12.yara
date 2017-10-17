import "hash"

rule m3e9_30a56a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.30a56a48c0000b12"
     cluster="m3e9.30a56a48c0000b12"
     cluster_size="67 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a2189339d1c3283aa982bf26b8e8035e', '7dedf7be3a7fdf396c6f65ac6d8d32cf', '18a7a4d553d222a8c788db2d48e813c8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

