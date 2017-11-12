import "hash"

rule k3e9_52bd955696c31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52bd955696c31912"
     cluster="k3e9.52bd955696c31912"
     cluster_size="17 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['9e31120e1570663c977b5532ff2ea255', '819c0e07f345d40a7d1c75086e8000de', 'a98f424335aedb5c0ebde1c2020eafac']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(1024,1024) == "26081bed67b45b3bb0e82dcbd0808688"
}

