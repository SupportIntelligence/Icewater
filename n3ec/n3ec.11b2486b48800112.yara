import "hash"

rule n3ec_11b2486b48800112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11b2486b48800112"
     cluster="n3ec.11b2486b48800112"
     cluster_size="2549 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['0bd212f050feefe6c6842edd732e0057', '0035f2658e5288411683c52c00738267', '3f4bb7fd81ce20fc5384f8339e2b5186']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(59632,1028) == "c1f1138f1d0ffda23d3da9e3fd56fa5a"
}

