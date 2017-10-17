import "hash"

rule k3e9_56969a99c2200b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.56969a99c2200b14"
     cluster="k3e9.56969a99c2200b14"
     cluster_size="24 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['4773e86b507bab13c91f33935b630d39', 'b80dcffe49f2c74e02d57b95b6b2c742', '04b2fc980585517f1bc5f9d2968ff295']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(2048,1024) == "f1ce8d7e7f91199173f2c298214ee3c3"
}

