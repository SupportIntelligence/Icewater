import "hash"

rule m3e9_32c5ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.32c5ea48c0000b12"
     cluster="m3e9.32c5ea48c0000b12"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['4d9a25435b2966ee432f09bc904f9f5d', 'ab2312cdabdf7dada66bb69e7a6a239c', '2f8626d69941ea5bbb55a240e5a6af02']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

