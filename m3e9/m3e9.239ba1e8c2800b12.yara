import "hash"

rule m3e9_239ba1e8c2800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.239ba1e8c2800b12"
     cluster="m3e9.239ba1e8c2800b12"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['5ecb948e7ab498d15aff65f0d167f022', '40cee2f2117af3da2d0e003c1f297c85', 'c43ead0a798e348854dd63fbac9de1ef']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(56320,1024) == "ef3bfa08a1e4c28928df02bba0a783b9"
}

