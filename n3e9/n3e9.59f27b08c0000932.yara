import "hash"

rule n3e9_59f27b08c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.59f27b08c0000932"
     cluster="n3e9.59f27b08c0000932"
     cluster_size="5721 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="elemental cloud malicious"
     md5_hashes="['06da492e46fd78f1f4d09cd2f7a32e2c', '060bc5448abbbc516ddeb900636a4c91', '0358f97da74dec44f50e9668421bb5ff']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(290816,1024) == "21594919be7cd7fa9b88bf714aa6fb5f"
}

