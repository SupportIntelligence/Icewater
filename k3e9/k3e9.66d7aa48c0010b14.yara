import "hash"

rule k3e9_66d7aa48c0010b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.66d7aa48c0010b14"
     cluster="k3e9.66d7aa48c0010b14"
     cluster_size="684 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre jqiu bublik"
     md5_hashes="['cfedd8246a67c1945eedec811455a9e8', '7189c6417727076512a078cef33ac65b', '5cd37c798cb810309964ddbc1bb488c7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(7680,1280) == "991282cd2c3842f4e5421dddcee7a8f5"
}

