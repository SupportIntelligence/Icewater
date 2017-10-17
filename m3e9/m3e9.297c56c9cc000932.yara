import "hash"

rule m3e9_297c56c9cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.297c56c9cc000932"
     cluster="m3e9.297c56c9cc000932"
     cluster_size="486 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d101612ee4be3cb505db68016565d2c2', 'e7c17b626dd24f35ca5719fd419e5c28', 'ab354725048c59798e7b410d3562bfe9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(7552,1088) == "2db6a2f628f1b4640a72420586ffb011"
}

