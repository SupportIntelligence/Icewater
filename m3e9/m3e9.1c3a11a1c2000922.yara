import "hash"

rule m3e9_1c3a11a1c2000922
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1c3a11a1c2000922"
     cluster="m3e9.1c3a11a1c2000922"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy androm backdoor"
     md5_hashes="['41729d521224ce6a55399ee7592bf889', 'df48c664fdbdff5f71e0f1ece717e718', '98f97703b86754a279b89deb1144eebc']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(24576,1024) == "0dfc0e71a745ccacf205794e88ed4ec7"
}

