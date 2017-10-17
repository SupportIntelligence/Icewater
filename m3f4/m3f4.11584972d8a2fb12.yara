import "hash"

rule m3f4_11584972d8a2fb12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f4.11584972d8a2fb12"
     cluster="m3f4.11584972d8a2fb12"
     cluster_size="337 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor nanocore noancooe"
     md5_hashes="['c3ac0f1476d70bdbd15f72566a816146', '34aab42e135a563d1a3604dd74a5a746', 'ea8eb9f10b67b720db0170d4304bda13']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(99840,1024) == "b7b7780a7488ec74afdab839017db84b"
}

