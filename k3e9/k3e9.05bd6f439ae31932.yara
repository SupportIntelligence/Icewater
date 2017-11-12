import "hash"

rule k3e9_05bd6f439ae31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05bd6f439ae31932"
     cluster="k3e9.05bd6f439ae31932"
     cluster_size="2032 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="fdld nitol dropped"
     md5_hashes="['428a65696605a1e327330a2832ae2603', '0c9ecb5330ff4fa33dcffdfa1eeadb89', '020576bc29019e86df9b0b1043cf9027']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,1024) == "c5999b2aae920e6fc825cd5123f52641"
}

