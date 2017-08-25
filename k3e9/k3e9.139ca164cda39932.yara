import "hash"

rule k3e9_139ca164cda39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ca164cda39932"
     cluster="k3e9.139ca164cda39932"
     cluster_size="90 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c0fde62a15e7b42e31950d0e221e378b', 'e2b66a62b4823bc3b24b3bc7bf87b4b5', '0a988ef4838346d00791cab2ecafde07']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "b563a84f7e0646b6239c507115d8d4a4"
}

