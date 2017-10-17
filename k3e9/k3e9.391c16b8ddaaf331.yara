import "hash"

rule k3e9_391c16b8ddaaf331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8ddaaf331"
     cluster="k3e9.391c16b8ddaaf331"
     cluster_size="36 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['949f018a8ee42eaae5f90838e4d0a02b', 'c03aadcd6c2d0feaf55846f9c9ba032d', '5a779b4851b68279f23a6c62712e4868']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(10752,1024) == "65db0d47738d02e06c3af5c67e95d4ab"
}

