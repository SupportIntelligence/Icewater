import "hash"

rule n3ed_31a450a988801132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a450a988801132"
     cluster="n3ed.31a450a988801132"
     cluster_size="32 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['176c7a4603f2788df0581ae9ba1de2a8', '1cd9562664b625fea4ccad4aeb3aac61', '62ca0955e161f21d64b72de8eba50f9e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(282624,1024) == "5b08fbae40bbe53b0959bc11173e4d2a"
}

