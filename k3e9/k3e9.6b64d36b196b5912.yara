import "hash"

rule k3e9_6b64d36b196b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b196b5912"
     cluster="k3e9.6b64d36b196b5912"
     cluster_size="69 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['ad86230a37e8dd28a2f0efe7cc3f156c', 'aa5bd379615a657c50b45c21f091dc82', '5e112c8317c1affd9849ad8f824d421d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(19648,1036) == "dbc5e24a5c7f08cf7d6715f88a9b1785"
}

