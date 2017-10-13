import "hash"

rule m3e9_297c56c9cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.297c56c9cc000932"
     cluster="m3e9.297c56c9cc000932"
     cluster_size="277 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['e60b160ccbf1a466cfac844998e30175', '55fbe881103659eb6fcbd061fa53be3e', '3fbcb6d057854afa0938df6781d4a4c1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(7552,1088) == "2db6a2f628f1b4640a72420586ffb011"
}

