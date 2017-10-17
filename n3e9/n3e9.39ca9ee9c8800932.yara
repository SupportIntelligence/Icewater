import "hash"

rule n3e9_39ca9ee9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39ca9ee9c8800932"
     cluster="n3e9.39ca9ee9c8800932"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy backdoor finfish"
     md5_hashes="['a292865965d28b218b300d13f4287850', 'd25f3b8324304081fc624d3364ec5699', 'bfc00c8b7fea94522447040ce5c91763']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(410112,1076) == "ab5c78a222b72df8502930b7c2966067"
}

