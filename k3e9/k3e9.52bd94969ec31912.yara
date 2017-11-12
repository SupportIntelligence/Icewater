import "hash"

rule k3e9_52bd94969ec31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52bd94969ec31912"
     cluster="k3e9.52bd94969ec31912"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d4d1b6a4cdfc330b2f36fc28176ff7af', '5eba4f981195f3b9516d4425a13813b0', 'de813dd797a435a39628809dd6f8872d']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(1024,1024) == "26081bed67b45b3bb0e82dcbd0808688"
}

