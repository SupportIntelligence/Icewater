import "hash"

rule m3e9_31a56a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31a56a48c0000b12"
     cluster="m3e9.31a56a48c0000b12"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['7f7ea74f1030e32f1467388845d087f4', 'b819ebd7f2a2d0d8400992d02ab3f8ef', '1293c836134c379d1e3b96a78a2095d8']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

