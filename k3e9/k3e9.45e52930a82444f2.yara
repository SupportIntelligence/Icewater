import "hash"

rule k3e9_45e52930a82444f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45e52930a82444f2"
     cluster="k3e9.45e52930a82444f2"
     cluster_size="340 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9bac6fd5a6e566bc58bb4918f3eba357', 'ac9267a87df2e595a2b180c3b88db52d', 'bdf8382b50f0af4c882cec5c54f37e9a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(10752,256) == "cdb45c58a8e061e0a954c937bbb37d0c"
}

