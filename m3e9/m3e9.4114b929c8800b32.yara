import "hash"

rule m3e9_4114b929c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4114b929c8800b32"
     cluster="m3e9.4114b929c8800b32"
     cluster_size="259 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b552df7705cc5b15272ef60c84b7ac7a', 'b1d6bf5cb122e139e06cfe935bd4b84b', 'a1adc73d3f31172f80c5d27d8b9f8139']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(81408,1280) == "8f11f1406d481de44626ff778effb09b"
}

