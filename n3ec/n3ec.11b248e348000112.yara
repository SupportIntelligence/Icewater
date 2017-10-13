import "hash"

rule n3ec_11b248e348000112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11b248e348000112"
     cluster="n3ec.11b248e348000112"
     cluster_size="6311 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob vetor"
     md5_hashes="['0de306759e34a0ccef9226c8a36a1263', '16120889f9923062a2d3691d9d2eaa66', '14aead29ae5edc5f2333f945039012f1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(59632,1028) == "c1f1138f1d0ffda23d3da9e3fd56fa5a"
}

