import "hash"

rule k3e9_453665274e631932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.453665274e631932"
     cluster="k3e9.453665274e631932"
     cluster_size="20 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbna vobfus chinky"
     md5_hashes="['c79277001783ac5b40954ff7adcbda5d', '0d392fbd21db0f60f12d051d510d7127', 'a6811a48f7457eb1f53e0612cbf510ea']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(39936,1024) == "203fd2aac7bdf53fd5ad28d081427232"
}

