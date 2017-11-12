import "hash"

rule k3e9_50b933069da31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.50b933069da31932"
     cluster="k3e9.50b933069da31932"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ac50d5040ba216e7a71dc70c47b2efc9', '358ab8010fc5fc8f0948762f2673e836', 'ac50d5040ba216e7a71dc70c47b2efc9']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(6144,1024) == "f79c58d33e2db2633697540b31321cf1"
}

