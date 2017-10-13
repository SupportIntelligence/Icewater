import "hash"

rule n3e9_116601a7ca231512
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.116601a7ca231512"
     cluster="n3e9.116601a7ca231512"
     cluster_size="459 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['2444a1fd463c9f14f8bc4d467f86c955', '7a424dbdb3be6175e1ada1dddabe1881', '14afa3099a7fbb8ab7c0a54b579cef6f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(151040,1024) == "c10ec287aa138bf9e5e808f691c477ec"
}

