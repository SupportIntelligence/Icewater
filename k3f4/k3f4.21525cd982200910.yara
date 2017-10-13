import "hash"

rule k3f4_21525cd982200910
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.21525cd982200910"
     cluster="k3f4.21525cd982200910"
     cluster_size="1536 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy linkury toolbar"
     md5_hashes="['18ee250782905f51a54a98c0c63c078f', '0486361d085bf13bae910a2cd4d9f36b', '0373fa217e303e8720b6ec8abc1f2ba4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(31232,1536) == "613270e5a09d8bbbfdd558e35c0d3b40"
}

