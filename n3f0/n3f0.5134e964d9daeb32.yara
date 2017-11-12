import "hash"

rule n3f0_5134e964d9daeb32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.5134e964d9daeb32"
     cluster="n3f0.5134e964d9daeb32"
     cluster_size="1860 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious amonetize heuristic"
     md5_hashes="['1b7f2d635429bb485e26c3f2a2c4fa36', '09e420c806b5de6e1966207a8a07bf50', '1abec313f916233391f94db41b271bb0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(770560,1536) == "8e492d69ecedcb83b0a814cf24b2e4d4"
}

