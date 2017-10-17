import "hash"

rule m3e9_2f15db419b0bdb32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2f15db419b0bdb32"
     cluster="m3e9.2f15db419b0bdb32"
     cluster_size="97 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['99cec560371f0efe9ef4e3271e858200', 'e5307068ee9737667242650f6f1562db', '6cf8d3a659a6c70f5d2b61ef11192f02']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(144839,1027) == "febf1716191c5a5a02b575d7d53fc6a5"
}

