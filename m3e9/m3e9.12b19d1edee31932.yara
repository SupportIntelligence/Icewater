import "hash"

rule m3e9_12b19d1edee31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.12b19d1edee31932"
     cluster="m3e9.12b19d1edee31932"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zbot gepys kryptik"
     md5_hashes="['afde99b6fa650697adf20e0142c0a90b', 'b951c7d6bfd98458e2ec3c7f9a1b1821', 'addc409eb993b7fc6db543c669605896']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(1024,1072) == "df53f28ee84284b154b220dc2078215d"
}

