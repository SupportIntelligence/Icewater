import "hash"

rule k3e9_53379fe2d992d112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.53379fe2d992d112"
     cluster="k3e9.53379fe2d992d112"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a123422d8af047c5388109d5b6ccf916', '66c62c88fb50e05a4e555bcd3ba1773a', 'a4c4e9800ccafdca8b11ba1fa1ff24a1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1280) == "da879da1717d791298f0d119c43f9f2e"
}

