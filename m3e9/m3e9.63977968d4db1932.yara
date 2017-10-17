import "hash"

rule m3e9_63977968d4db1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.63977968d4db1932"
     cluster="m3e9.63977968d4db1932"
     cluster_size="561 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious heuristic adsearch"
     md5_hashes="['84bec8625704c55c80adff1dd6dc9977', '5cd204e611a854d4146e80799251a136', '3e89616ed58bc81ab3470dc840e3a436']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(124110,1126) == "65176acda143da0f5606f0609ed438ce"
}

