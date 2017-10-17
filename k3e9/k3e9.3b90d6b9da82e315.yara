import "hash"

rule k3e9_3b90d6b9da82e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b90d6b9da82e315"
     cluster="k3e9.3b90d6b9da82e315"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['c4e7e7dc6123de4869f396d33f9ffdb8', 'c31fe7bc9759b8d74573ace0653ea1be', 'c3cfd8dd0f6fb1264c1a0179e5a6c1be']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1195) == "85494117da9d5bcf1e5f49bc29469b49"
}

