import "hash"

rule n3ed_31a444d7aa211132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a444d7aa211132"
     cluster="n3ed.31a444d7aa211132"
     cluster_size="19 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['61067f414b0d6bf45c1bad8def3a57d5', '61067f414b0d6bf45c1bad8def3a57d5', 'c2d2e4c8a2927a2aeea94016f397be4f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(199680,1024) == "494ca29c111fe1e5f008c4abb7f6b854"
}

