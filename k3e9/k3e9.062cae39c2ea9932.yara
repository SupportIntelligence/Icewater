import "hash"

rule k3e9_062cae39c2ea9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.062cae39c2ea9932"
     cluster="k3e9.062cae39c2ea9932"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor berbew qukart"
     md5_hashes="['87f2974ec05cd558c1a9ce1f2fc1d7b7', 'c3dc776166fa948644d9f009ad40e898', 'c3dc776166fa948644d9f009ad40e898']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

