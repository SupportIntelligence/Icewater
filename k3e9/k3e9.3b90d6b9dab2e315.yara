import "hash"

rule k3e9_3b90d6b9dab2e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b90d6b9dab2e315"
     cluster="k3e9.3b90d6b9dab2e315"
     cluster_size="45 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['23b541044d02371708d17aeab2ace866', '2ce7df6f1789f5f6808ecd7f46bb2679', 'cc8610286bfc25723fe1e00a74b984a5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1195) == "85494117da9d5bcf1e5f49bc29469b49"
}

