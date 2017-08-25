import "hash"

rule k3e9_51b13316dda31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13316dda31b32"
     cluster="k3e9.51b13316dda31b32"
     cluster_size="835 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9714b191f5aa46e75fa6fdde44e4f891', '2c0ec9ab90bcd3e95ef269fa62a92fdb', 'adba8af281e3f12316917e0f083e69e2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(23296,256) == "079e9b39d5afe54fca5c89fccbb1f593"
}

