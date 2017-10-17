import "hash"

rule k3e9_61149464e8244efa
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.61149464e8244efa"
     cluster="k3e9.61149464e8244efa"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['788acb7cb727ebffde06d4516b16774c', 'd8b540271df448e5b3d3c9bdff8ffd9b', 'd8b540271df448e5b3d3c9bdff8ffd9b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(36864,1024) == "18222a2ab65400d38cf6862a902f1e8e"
}

