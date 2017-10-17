import "hash"

rule n3e9_29c605e4ea208b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c605e4ea208b12"
     cluster="n3e9.29c605e4ea208b12"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="crypt cuegoe trojandropper"
     md5_hashes="['b12e84b84c73c3c252d887bc8fad3676', 'eafaaeba344631e5c5ed2ce5ca5ec512', 'b12e84b84c73c3c252d887bc8fad3676']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(532460,1028) == "00fc4f62daf0da374568acfeb55d7e7f"
}

