import "hash"

rule m3e9_699b0db9d3a20912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.699b0db9d3a20912"
     cluster="m3e9.699b0db9d3a20912"
     cluster_size="220 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c4c302fe29398705eececfdb30850067', '833063e1e11fb1053d57653204f62bf7', '9750ef0a31b962ad99430c46953498fd']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(118784,1024) == "0b13af27dca6566af14dbe01edad49b3"
}

