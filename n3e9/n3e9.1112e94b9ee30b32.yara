import "hash"

rule n3e9_1112e94b9ee30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1112e94b9ee30b32"
     cluster="n3e9.1112e94b9ee30b32"
     cluster_size="11713 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="downloadguide unwanted ceeee"
     md5_hashes="['0077f2afc4af7b6fd59cd7bb9e209e6e', '017fd4449f9f52ef1c95dbb2e1254aba', '02448bcdf81848439a7686ffa3388429']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(543360,1088) == "5dbe9c0bea6b4ae6a40260573985bd66"
}

