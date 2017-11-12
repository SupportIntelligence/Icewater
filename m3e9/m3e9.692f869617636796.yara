import "hash"

rule m3e9_692f869617636796
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692f869617636796"
     cluster="m3e9.692f869617636796"
     cluster_size="90 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="otwycal wapomi vjadtre"
     md5_hashes="['da1869e00213db948b4470ad7d894ecc', 'c62d1854de64f8d6ca9c828bae79a5bd', 'e473fbdce8a15827e72ada9be0f13bf4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "17bb2f77974ec7dfe7028de9f705c059"
}

