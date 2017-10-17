import "hash"

rule n3e9_39c29569c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c29569c8800b12"
     cluster="n3e9.39c29569c8800b12"
     cluster_size="358 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy trojandropper backdoor"
     md5_hashes="['a3c6fe98ceb20798859f05a62a9d7d92', 'a62602d350e408c71b3911708db0ec3d', 'cc1f0e9b4cb1c588420e5ed9048819f4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(138262,1046) == "66a1aad2b922cc836352280ff4cf1d3b"
}

