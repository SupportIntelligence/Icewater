import "hash"

rule n3e9_5b989cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5b989cc1cc000b12"
     cluster="n3e9.5b989cc1cc000b12"
     cluster_size="13132 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="autoit vmlfrbwxs autorun"
     md5_hashes="['0d68078eb85401a6f3913ef7615b2344', '10b374768a9e2158d504861064c33080', '165cb2f8c3add6399667c632d3a899f4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(331264,1024) == "c01dc46f32bdd57e127b56fe3da46d13"
}

