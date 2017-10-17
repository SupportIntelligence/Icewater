import "hash"

rule n3e9_53bb72c1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.53bb72c1c4000912"
     cluster="n3e9.53bb72c1c4000912"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious dangerousobject heuristic"
     md5_hashes="['385cd9a576734c2912d47e5e8c157975', '385cd9a576734c2912d47e5e8c157975', '17658b2ecc8128c7ffe48f88cdf3e853']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(344064,1024) == "cbc088f20be9a912cb3ab73765de8223"
}

