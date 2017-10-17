import "hash"

rule m3e9_5942dc6251aad6f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5942dc6251aad6f2"
     cluster="m3e9.5942dc6251aad6f2"
     cluster_size="105 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef autorun"
     md5_hashes="['db5cc7ea7b5dd3c5691bdfef52fb0880', 'cbf14a5bb367bbeb5a01c04b5a173500', '6689659e2c56c155887886cd7f657420']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(134144,1024) == "5cd73e774fedfe2b38e981dc219c9428"
}

