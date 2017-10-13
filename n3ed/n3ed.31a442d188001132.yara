import "hash"

rule n3ed_31a442d188001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a442d188001132"
     cluster="n3ed.31a442d188001132"
     cluster_size="60 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b8cc414db70f24498a1587abcf2f2caf', '4978a57e41d356fc0f4295638453424c', 'a27eaa6abef371eda23829bfe3c06fad']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(282624,1024) == "5b08fbae40bbe53b0959bc11173e4d2a"
}

