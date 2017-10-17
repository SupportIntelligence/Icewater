import "hash"

rule n3e9_235708e3c6420b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.235708e3c6420b12"
     cluster="n3e9.235708e3c6420b12"
     cluster_size="65038 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="autorun hybris yuner"
     md5_hashes="['0246ee75d55383a7ef64f8b290829faf', '01a4ec2a7563d19314c0d3fa389e672d', '005d6d62969a1ab6574f26c53a27a060']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(480768,1024) == "1d9ed8c5c96bed6995fc59db76099d52"
}

