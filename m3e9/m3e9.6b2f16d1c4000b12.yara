import "hash"

rule m3e9_6b2f16d1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f16d1c4000b12"
     cluster="m3e9.6b2f16d1c4000b12"
     cluster_size="21387 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="nimnul vjadtre wapomi"
     md5_hashes="['0b36f841f9bdb943e191ab037878af89', '03ea8e5276e41a53edf39cc80c63a115', '00241363bfdbbc0e9fb2b602caa9ffb4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(71680,1024) == "df267315ded7f5392d705fd520e811af"
}

