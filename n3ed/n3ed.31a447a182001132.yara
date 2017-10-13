import "hash"

rule n3ed_31a447a182001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a447a182001132"
     cluster="n3ed.31a447a182001132"
     cluster_size="68 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['d504f973e0099730b9bc241791c52aa1', 'e07a0c08d9b6a503b9411c1344384b0e', '1451be8e6471edc128cdf8c894c97045']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(282624,1024) == "5b08fbae40bbe53b0959bc11173e4d2a"
}

