import "hash"

rule k3e9_410e2595a5254a66
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.410e2595a5254a66"
     cluster="k3e9.410e2595a5254a66"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['594d854cf51ea87825fa5ceee97f3c1e', '664b6ecdc35630e56347d632e0d0b523', '664b6ecdc35630e56347d632e0d0b523']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(29526,1109) == "8a276caafdbf30bba5d7fac2a3e0c83d"
}

