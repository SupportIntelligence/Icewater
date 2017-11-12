import "hash"

rule m3e9_2d964b26ea008932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2d964b26ea008932"
     cluster="m3e9.2d964b26ea008932"
     cluster_size="159 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a208e771c4604f41c846f2cd86b2466c', 'ac19a554a5055e585f622bce7a5f61ba', 'c903ee9cd8b08b3865ef3b90122a52ee']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(73728,1024) == "d0d038130aeb82cf87189ddf5ec47c53"
}

