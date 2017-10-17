import "hash"

rule k3e9_6946fa7b61046396
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6946fa7b61046396"
     cluster="k3e9.6946fa7b61046396"
     cluster_size="26 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c79c3a970c0942662d8284b5679a6691', 'e9d5b7908a912ca71e0c4a839abec87b', '23e624cfbba609cfb41952e60c22b765']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18723,1041) == "f56d85d5e204fe8b22ff7546c043c8f3"
}

