import "hash"

rule k3e9_52bd969696c31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52bd969696c31912"
     cluster="k3e9.52bd969696c31912"
     cluster_size="53 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d18d3d6a14ef03867a9ccb4930e4b618', 'cc6a5877dc53dde189e2eee39a5d3460', '52250c679c75bd96183461283eb2806a']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(5120,1024) == "177790c0127a5a5ab5ac5824b96ec385"
}

