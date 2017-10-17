import "hash"

rule n3e9_31cb9041cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31cb9041cc000932"
     cluster="n3e9.31cb9041cc000932"
     cluster_size="72 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['bf9668bbef1c5d26a5fc135a9984422d', '6c38ccfa377f3311e724aed78236504a', 'bd6b91624bc3ea70fc4e9dc735f196ac']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(142763,1109) == "3e153f591f3d402724f89d1593be1ca7"
}

