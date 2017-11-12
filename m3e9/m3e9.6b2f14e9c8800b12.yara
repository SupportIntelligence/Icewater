import "hash"

rule m3e9_6b2f14e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f14e9c8800b12"
     cluster="m3e9.6b2f14e9c8800b12"
     cluster_size="176 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c00f5d3fea2694778da34a8edcba4833', 'b8c37dc002413f23480a5c265bfc28eb', 'da7c6e11b0298eba75b19ef5a23c2240']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27648,1024) == "4e761ac11d30dc1172b0b33bfd79719a"
}

