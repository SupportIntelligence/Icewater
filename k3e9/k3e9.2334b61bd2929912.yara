import "hash"

rule k3e9_2334b61bd2929912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2334b61bd2929912"
     cluster="k3e9.2334b61bd2929912"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qukart backdoor berbew"
     md5_hashes="['cba5b2bed56720293463784b4bc0cab3', 'caef7f1ac894eda774d34c6388b0923a', 'caef7f1ac894eda774d34c6388b0923a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

