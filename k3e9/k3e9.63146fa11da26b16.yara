import "hash"

rule k3e9_63146fa11da26b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fa11da26b16"
     cluster="k3e9.63146fa11da26b16"
     cluster_size="141 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b00eeb9c5a44a77c2b1e2e76411c4996', 'cf81f665e13c55bb30de8c9fff60bb97', 'a8d061c0026151b42c319ac6af4fa3ea']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

