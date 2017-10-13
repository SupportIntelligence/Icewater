import "hash"

rule k3ec_52a69299c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.52a69299c6200b12"
     cluster="k3ec.52a69299c6200b12"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['b2a4635b40ee8b5ba7debc910f23c47e', 'bf2c081ea87b388fbcd94d610c384771', '74c8c7c1f0fc3df06a068f09034f8101']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9728,1024) == "75b5de20691f7b39f4a72b65a4c77b87"
}

