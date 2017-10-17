import "hash"

rule k3e9_61149464e8344ef2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.61149464e8344ef2"
     cluster="k3e9.61149464e8344ef2"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b9ef03d20ac7576be6256395672d9860', '71d079eaa0c3aa1b35031d393129998b', '71d079eaa0c3aa1b35031d393129998b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(36864,1024) == "18222a2ab65400d38cf6862a902f1e8e"
}

