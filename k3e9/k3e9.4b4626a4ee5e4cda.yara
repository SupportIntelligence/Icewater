import "hash"

rule k3e9_4b4626a4ee5e4cda
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ee5e4cda"
     cluster="k3e9.4b4626a4ee5e4cda"
     cluster_size="64 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ce04aca5ceafa92c80042f8ba896d966', 'e4516c457264d1b2cb4dd6063d4bcd76', 'a6293726e4ff8bedf0c825bdd4ff268b']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(38400,1280) == "8d605714fc674665af1478a4a862ce98"
}

