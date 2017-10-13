import "hash"

rule m3e7_231c6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.231c6a48c0000b12"
     cluster="m3e7.231c6a48c0000b12"
     cluster_size="112 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['c157780c28e5e85008ddf56de88afb4f', '5a3fecd4ac85fa7989eb1567e03a8ad9', 'b011ae1720fdb4afac69b4f7d96d4b6e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62320,1115) == "6bdc6a4f47625879cbac9626b36ace17"
}

