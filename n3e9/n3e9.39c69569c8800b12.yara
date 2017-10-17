import "hash"

rule n3e9_39c69569c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c69569c8800b12"
     cluster="n3e9.39c69569c8800b12"
     cluster_size="765 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy trojandropper backdoor"
     md5_hashes="['9166323934b5d4aa602087b542d0e7ec', '044c9c276df6ce83824f67f1082027e7', '1c53ebdd036932359ed7a137256cb28e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(138262,1046) == "66a1aad2b922cc836352280ff4cf1d3b"
}

