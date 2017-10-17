import "hash"

rule k3f9_6396d6456b2ac6ba
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.6396d6456b2ac6ba"
     cluster="k3f9.6396d6456b2ac6ba"
     cluster_size="1026 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bdmj genpack malicious"
     md5_hashes="['45bd96b184e97003f74bcc95134cab02', '33e6db4ba25a9e55bc7ff027cc827cdc', '3d601a6ec0bfd27f6783c3890af21d60']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1024) == "5828763f8425415a6b2cfee53769803c"
}

