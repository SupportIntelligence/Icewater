import "hash"

rule m3e9_4b6fa441c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4b6fa441c0000912"
     cluster="m3e9.4b6fa441c0000912"
     cluster_size="38 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre kryptik malicious"
     md5_hashes="['c0f755a42f04d237dc27bb12229846fb', 'ba1adfe2fe62c1d2a2096cc523c19563', 'c0f755a42f04d237dc27bb12229846fb']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64000,1024) == "c5fb606aebff5d97a6aa14ec0b199377"
}

