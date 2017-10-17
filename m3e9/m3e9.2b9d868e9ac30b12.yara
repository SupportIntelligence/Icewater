import "hash"

rule m3e9_2b9d868e9ac30b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b9d868e9ac30b12"
     cluster="m3e9.2b9d868e9ac30b12"
     cluster_size="42 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zboter tinba malicious"
     md5_hashes="['5465190aa79e227042b7615523d7992e', 'd835f59b89580b373178e9c257155cec', 'cfddbc1047a863651ff4cba91de74817']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(70656,1024) == "c2e7fa0510bfd54aa28de969c274ca12"
}

