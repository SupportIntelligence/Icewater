import "hash"

rule m3e9_231ba1e8c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.231ba1e8c2000b12"
     cluster="m3e9.231ba1e8c2000b12"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b9d39fa7fdcddb694c010975be81cef5', 'e563e1a2e578ec0f86634d929e2a16f5', '7ed6b884404af3aff0a06cb6674daaf6']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(56320,1024) == "ef3bfa08a1e4c28928df02bba0a783b9"
}

