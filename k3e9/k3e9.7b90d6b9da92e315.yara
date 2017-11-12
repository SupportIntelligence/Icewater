import "hash"

rule k3e9_7b90d6b9da92e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.7b90d6b9da92e315"
     cluster="k3e9.7b90d6b9da92e315"
     cluster_size="55 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['abe847db392ddb18233a0eec6a2482e6', 'b8b08ae0344bdfbb6525ab97ebf49ba5', 'abe847db392ddb18233a0eec6a2482e6']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(14336,1024) == "ea6edfd2f8b00ea802d0c1920b2555fd"
}

