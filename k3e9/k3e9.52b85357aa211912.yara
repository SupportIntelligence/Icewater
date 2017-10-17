import "hash"

rule k3e9_52b85357aa211912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52b85357aa211912"
     cluster="k3e9.52b85357aa211912"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['a617d53ae3894251aec9fd7677fa9960', 'd2c6cb2d556cd1b71e4385b3450908b8', '58656ab3a47a889251c7bd272408804c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9560,1066) == "41225ea7cd7bc5ea699676982c5b42ce"
}

