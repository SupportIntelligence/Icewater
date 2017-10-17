import "hash"

rule k3e9_6a66a58ba6220100
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a66a58ba6220100"
     cluster="k3e9.6a66a58ba6220100"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['c7f2cdeaabba9a8c738401c4aa5037a2', 'c7f2cdeaabba9a8c738401c4aa5037a2', 'a6c2e5c252527e59f82e07df519f1a97']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "97f75fe12623e289ad4cfba47d792603"
}

