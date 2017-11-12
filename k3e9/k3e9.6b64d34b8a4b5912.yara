import "hash"

rule k3e9_6b64d34b8a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b8a4b5912"
     cluster="k3e9.6b64d34b8a4b5912"
     cluster_size="886 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['a6f7bc0a7c0eed4e750e42fbe54aa557', 'a4a2f38fed645855848f2583a7e77d90', 'a09aabcd937c462ceaae49b98923684d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(3072,1036) == "a9d8654475cb556fb1cf62b83e2fa778"
}

