import "hash"

rule o3ed_539446c6ce230b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539446c6ce230b12"
     cluster="o3ed.539446c6ce230b12"
     cluster_size="86 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['ce8cd283ca7a71327873ab46deaa1960', 'c24ccd285923225ffaf804da27a8a6e8', 'a9b505ed47f9f8ca818005f9ad1fcfc2']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1646592,1024) == "212ae30c5ded1d85044a3327f766f3a2"
}

