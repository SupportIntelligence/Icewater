import "hash"

rule n3e9_53ab72c1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.53ab72c1c4000912"
     cluster="n3e9.53ab72c1c4000912"
     cluster_size="19 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious dangerousobject heuristic"
     md5_hashes="['5ef513ccd14b61f14d39f0eb8246a576', '0c9be80b33c6d9f54c9a80a42564f0e6', 'c44d1795d59dca5abda897b51a1b3c55']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(344064,1024) == "cbc088f20be9a912cb3ab73765de8223"
}

