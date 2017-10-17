import "hash"

rule k3e9_05355856ddbb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05355856ddbb1932"
     cluster="k3e9.05355856ddbb1932"
     cluster_size="20 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['f60bb422af85db2f85e212a5483dbdf1', 'b7a199e71b9dd867dcd835e59a39298b', 'f60bb422af85db2f85e212a5483dbdf1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17408,1024) == "0fe9e98508ccf8e184d819bf21b5ad2b"
}

