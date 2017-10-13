import "hash"

rule o3e9_5bbcea48c0001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.5bbcea48c0001912"
     cluster="o3e9.5bbcea48c0001912"
     cluster_size="276 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="softpulse bundler riskware"
     md5_hashes="['a684388d1370e755f4122c1d00c0c82e', '4d6db6c95695b461a8775b7842a88ea7', '6785212f35e5f74f21dfda7b74e345e5']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(5120,1024) == "5c0e297b041fd59f6979e90497481630"
}

