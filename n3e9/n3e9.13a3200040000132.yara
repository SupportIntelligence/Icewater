import "hash"

rule n3e9_13a3200040000132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13a3200040000132"
     cluster="n3e9.13a3200040000132"
     cluster_size="2814 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack jadtre"
     md5_hashes="['8d1b0060c3c8f2fdfd88f5cd12007345', 'a5c1557f7edd044b7dad4dc7d394f6aa', '94bc7011cbece6aeda5ed8c873cace0a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(130560,1024) == "bedc31b60d0d07a39db8e3f5a37c10e2"
}

