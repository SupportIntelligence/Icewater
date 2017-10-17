import "hash"

rule n3e9_529b1da1ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.529b1da1ca000b12"
     cluster="n3e9.529b1da1ca000b12"
     cluster_size="357 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="symmi virut advml"
     md5_hashes="['3051a89d6470138feaa45c05b80d469c', '9ad8b0368a5a4a292503aec8e354f45b', 'b0d5725caddc79b9306a1a78f3e1c803']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(249344,1280) == "d052851a87d4a355e59493a7e3057272"
}

