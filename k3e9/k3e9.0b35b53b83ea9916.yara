import "hash"

rule k3e9_0b35b53b83ea9916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b35b53b83ea9916"
     cluster="k3e9.0b35b53b83ea9916"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qukart backdoor berbew"
     md5_hashes="['b554819ac60c8a43a00adcdadc3e68e1', 'b554819ac60c8a43a00adcdadc3e68e1', 'b554819ac60c8a43a00adcdadc3e68e1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

