import "hash"

rule k3e9_131cae1bc29a9916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.131cae1bc29a9916"
     cluster="k3e9.131cae1bc29a9916"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor berbew qukart"
     md5_hashes="['be2d0edc78bfc3100a1a76c2479f9f1e', 'be2d0edc78bfc3100a1a76c2479f9f1e', '3609c46129f1cd0d73c5aa75a8454cd4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

