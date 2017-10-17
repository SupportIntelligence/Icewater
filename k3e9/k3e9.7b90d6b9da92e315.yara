import "hash"

rule k3e9_7b90d6b9da92e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.7b90d6b9da92e315"
     cluster="k3e9.7b90d6b9da92e315"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['d4f24485e95a1b81a0bcdbf648de08ee', 'd4f24485e95a1b81a0bcdbf648de08ee', '2a281c1b38c36df8e8371f6208f48a50']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1195) == "85494117da9d5bcf1e5f49bc29469b49"
}

