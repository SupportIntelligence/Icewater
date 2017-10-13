import "hash"

rule m3e9_71b05cc3cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.71b05cc3cc000932"
     cluster="m3e9.71b05cc3cc000932"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['cdc8f73addf53702bbc36f1159d4e487', '27a8f093294e5d07ab454baa55999836', '27a8f093294e5d07ab454baa55999836']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(45056,1024) == "fa9c25955b891a271b1cefbcca5d296d"
}

