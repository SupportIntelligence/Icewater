import "hash"

rule k3e9_4162d587ea601112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4162d587ea601112"
     cluster="k3e9.4162d587ea601112"
     cluster_size="10 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['6712c8c12204a88d3fef15578808293c', '6712c8c12204a88d3fef15578808293c', '89fbd4879765d7abe170941f2dfd8a44']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "c6e0a64fce02608f75de0e6323f758c0"
}

