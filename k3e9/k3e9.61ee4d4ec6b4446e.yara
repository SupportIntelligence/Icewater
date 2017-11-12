import "hash"

rule k3e9_61ee4d4ec6b4446e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.61ee4d4ec6b4446e"
     cluster="k3e9.61ee4d4ec6b4446e"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b02cddda26a8e2bb9914dd391a186583', 'b02cddda26a8e2bb9914dd391a186583', 'a15d3f93d427b988491a95c63b6a7952']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

