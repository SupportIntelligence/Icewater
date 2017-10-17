import "hash"

rule k3e9_592e846b42220932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.592e846b42220932"
     cluster="k3e9.592e846b42220932"
     cluster_size="26 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="chinky vbna autorun"
     md5_hashes="['3ead8c826dab886b7aef882f73d147a4', '4dd7ad9c0065aeb1a7ea95fc62fddc9c', 'b3c867b6d8ce5e55afd7a288222764b8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,1024) == "544d7750ecacc0001d7094f51854ff6a"
}

