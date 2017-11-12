import "hash"

rule k3e9_61ee4d46c6b6444e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.61ee4d46c6b6444e"
     cluster="k3e9.61ee4d46c6b6444e"
     cluster_size="32 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c5e142694b771b9cfd0ccd8c3ef73a7b', 'abee8ce12e540f864d3ac4bc0d56620c', 'c5e142694b771b9cfd0ccd8c3ef73a7b']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

