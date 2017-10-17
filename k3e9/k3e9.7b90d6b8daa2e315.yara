import "hash"

rule k3e9_7b90d6b8daa2e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.7b90d6b8daa2e315"
     cluster="k3e9.7b90d6b8daa2e315"
     cluster_size="19 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['282a09871928b96eda1dd9878e87d430', '173b25e621179f22fa1d53c74160a3b7', '40d56d525153e54eb904d9e619bb9880']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9216,1024) == "876e9a845e43150f15186ffda01fff89"
}

