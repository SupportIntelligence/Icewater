import "hash"

rule o3e9_1b9c3a89c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1b9c3a89c4000b32"
     cluster="o3e9.1b9c3a89c4000b32"
     cluster_size="51 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy malicious attribute"
     md5_hashes="['120a8a71709ec4bdf1a9350920b43c50', '2bc10913447e3819ce05b197109882ff', '5ee0ff8b35835cae35d31907f6dd26c3']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1248436,1033) == "5bbff87fb1ab2a0846c4c88bec85e33d"
}

