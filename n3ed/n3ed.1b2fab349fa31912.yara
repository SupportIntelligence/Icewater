import "hash"

rule n3ed_1b2fab349fa31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b2fab349fa31912"
     cluster="n3ed.1b2fab349fa31912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['48dbab851130ba52634eab7a9df38a7c', 'c2740d2526868609a6f09d0deed7f7a1', 'c2740d2526868609a6f09d0deed7f7a1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(296995,1059) == "529f9aec791a33f80d7be972c607e7b7"
}

