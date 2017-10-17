import "hash"

rule k3e9_61ee4d46c6b6444e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.61ee4d46c6b6444e"
     cluster="k3e9.61ee4d46c6b6444e"
     cluster_size="27 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['08e3edcca4d308d759bb018b1cf32cb5', 'abc09d072a962bfb3de410441671fe8d', 'e4971fb2fc2fe2c6e81df1dc8e0e7f76']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

