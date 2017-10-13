import "hash"

rule p3e9_111d5ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.111d5ec1cc000b12"
     cluster="p3e9.111d5ec1cc000b12"
     cluster_size="228 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ircbot backdoor dorv"
     md5_hashes="['c6fb80f5ccab6e5e71b60db38db79f4c', 'bdf14910a3433ca1bf60376ae1d7d463', 'dd04f19515ef15c333ae7777e278c349']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(79788,1030) == "d3e5be795e3c1744053621665c7c209d"
}

