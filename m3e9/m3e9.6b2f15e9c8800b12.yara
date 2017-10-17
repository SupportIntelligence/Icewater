import "hash"

rule m3e9_6b2f15e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f15e9c8800b12"
     cluster="m3e9.6b2f15e9c8800b12"
     cluster_size="20 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c3598d7902f3af1642c0461cc88638b6', 'b76627c244b84267830b64b887e2149b', 'c2bb5245e3ce50dd3912714abf186728']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27648,1024) == "4e761ac11d30dc1172b0b33bfd79719a"
}

