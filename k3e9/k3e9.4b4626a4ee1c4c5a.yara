import "hash"

rule k3e9_4b4626a4ee1c4c5a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ee1c4c5a"
     cluster="k3e9.4b4626a4ee1c4c5a"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['7c4a688380483da7023693f684e6547b', '7c4a688380483da7023693f684e6547b', 'e8bed821073d0e372afc002210a9bdc3']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(38400,1280) == "8d605714fc674665af1478a4a862ce98"
}

