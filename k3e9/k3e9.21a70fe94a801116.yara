import "hash"

rule k3e9_21a70fe94a801116
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.21a70fe94a801116"
     cluster="k3e9.21a70fe94a801116"
     cluster_size="67735 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="generickd androm backdoor"
     md5_hashes="['0190a39fb03860f360bf80b1ffe9bc0c', '028ac1e02c13d6f1b393fb950e874740', '015b1accffc7b952c88691e22a233c81']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9728,1024) == "4ab982450c4169cb439580b13a70fedd"
}

