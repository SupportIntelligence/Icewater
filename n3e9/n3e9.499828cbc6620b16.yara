import "hash"

rule n3e9_499828cbc6620b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.499828cbc6620b16"
     cluster="n3e9.499828cbc6620b16"
     cluster_size="20 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['48f95ae890ac593786a6798c8e6dbe72', 'ca6611ce6b3976260c7dfd98cd97f909', 'b22d34ecd176a8f8cc5f8ecb6c19561f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(436736,1024) == "b7a5262ff43994734cf2fccdbf263cf3"
}

