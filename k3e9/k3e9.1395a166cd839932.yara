import "hash"

rule k3e9_1395a166cd839932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395a166cd839932"
     cluster="k3e9.1395a166cd839932"
     cluster_size="57 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a97c7051ef82cc358e30108b84d3de66', 'b8bb81873f69589528ab65561cd7c6af', '5693cc82410f7f0a4e7842823431f519']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,1024) == "de88ae07cff08473a9c10f1d9aaff856"
}

