import "hash"

rule m3e9_7116cda29dbe7b36
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7116cda29dbe7b36"
     cluster="m3e9.7116cda29dbe7b36"
     cluster_size="69 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbinject wbna"
     md5_hashes="['c7d4de31177434381f4555a22d4843e4', 'b45612def50783300024a3978f7a4519', 'c7d4de31177434381f4555a22d4843e4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(198656,1024) == "717cdae274e7ffe32ba8a1090986f9cc"
}

