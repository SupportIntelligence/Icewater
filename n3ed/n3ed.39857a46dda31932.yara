import "hash"

rule n3ed_39857a46dda31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39857a46dda31932"
     cluster="n3ed.39857a46dda31932"
     cluster_size="47 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['45ac61268771f42e1e7f209d7c3c0d20', '62359168e2b42a7d426ee6e2991a323b', 'c4cd0febb86359140daf3683c5e57484']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(371712,1024) == "18dbd5f35c723e3b2d0cc3baafc60c36"
}

