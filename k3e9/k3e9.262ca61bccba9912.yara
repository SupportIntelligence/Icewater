import "hash"

rule k3e9_262ca61bccba9912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.262ca61bccba9912"
     cluster="k3e9.262ca61bccba9912"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="berbew qukart backdoor"
     md5_hashes="['01567b465986fe52f057ec20f9e7e3ee', 'a9090185ade5ca709c586f8c2af87857', 'b8e51d2000f2bf2e7151b90f4aad3c98']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

