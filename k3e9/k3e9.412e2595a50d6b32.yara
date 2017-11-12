import "hash"

rule k3e9_412e2595a50d6b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.412e2595a50d6b32"
     cluster="k3e9.412e2595a50d6b32"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a2299df926e84e75b3d99fc8fef87e99', '7b3fbe80a8019af0e3aacfe82c00268d', 'c46a488bf7fbb8ac25ea10723155d8de']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(29526,1109) == "8a276caafdbf30bba5d7fac2a3e0c83d"
}

