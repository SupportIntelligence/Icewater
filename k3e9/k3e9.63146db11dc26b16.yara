import "hash"

rule k3e9_63146db11dc26b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146db11dc26b16"
     cluster="k3e9.63146db11dc26b16"
     cluster_size="27 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['0e7308dd07e62c3b72f2e912c18d0085', 'cfd858b74e8856fc4c61856d6cd2956a', 'ac811daad8d53d7dc5f0d953b7364104']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

