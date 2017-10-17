import "hash"

rule k3e9_3b90d6b9da8ae315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b90d6b9da8ae315"
     cluster="k3e9.3b90d6b9da8ae315"
     cluster_size="32 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['1751ae929c539811bfd95b4f9a3850ea', 'c44427adb847ef53c244ea9d134a5e7b', 'c07a6e289e756741983c42da43a1e977']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "a542a74c6ab6d51db649cc8e7460a4ba"
}

