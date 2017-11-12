import "hash"

rule k3e9_42146134dda30b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.42146134dda30b10"
     cluster="k3e9.42146134dda30b10"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['9cade354070b60103d8b2e0de9242a30', '6fb9c65ae3a1d003665d089ad379a371', '6fb9c65ae3a1d003665d089ad379a371']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(5236,1053) == "f906a3bcdc2f7c6cc54ba5e3cf5278e7"
}

