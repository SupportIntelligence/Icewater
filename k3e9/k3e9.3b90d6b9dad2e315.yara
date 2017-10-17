import "hash"

rule k3e9_3b90d6b9dad2e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b90d6b9dad2e315"
     cluster="k3e9.3b90d6b9dad2e315"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['c2139199f61abfa3bcd99ea43940177a', 'c2139199f61abfa3bcd99ea43940177a', 'c2139199f61abfa3bcd99ea43940177a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1195) == "85494117da9d5bcf1e5f49bc29469b49"
}

