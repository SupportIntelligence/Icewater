import "hash"

rule n3e9_32968f9da6210b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.32968f9da6210b14"
     cluster="n3e9.32968f9da6210b14"
     cluster_size="364 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob sality"
     md5_hashes="['d258bd8689c73c209b4214f59a6fd934', '3e591d6a8e2558789e6319921a731ef8', 'f4de4af79146fae7afe213683e1eb528']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(107520,1024) == "99b9f1d7451f15945536d5e3fb429c0a"
}

