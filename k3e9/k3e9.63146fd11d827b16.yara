import "hash"

rule k3e9_63146fd11d827b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fd11d827b16"
     cluster="k3e9.63146fd11d827b16"
     cluster_size="28 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b937a6a3031a37e4620c167abe5f409f', '509cc930f1463167b86ea1f0fe5c3d4d', 'c2718054280b8634f0ae6a7234392ad1']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

