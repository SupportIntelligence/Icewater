import "hash"

rule j3e9_4b73a12cc6400b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.4b73a12cc6400b16"
     cluster="j3e9.4b73a12cc6400b16"
     cluster_size="450 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="fileinfector ayjs malicious"
     md5_hashes="['b3b9d8c19fd287bd0674825bf246ce98', '4d8eb42b100aa5742486a887948c5381', 'a52a1d1547315a9a165dccbd81d89ce4']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(10752,1024) == "2374ce1f4c2006e8aa275ac08e78e64b"
}

