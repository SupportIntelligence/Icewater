import "hash"

rule k3e9_139da164dcd39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164dcd39932"
     cluster="k3e9.139da164dcd39932"
     cluster_size="177 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ad989873d462bd7a218cf7fe343d94dd', 'c2e3a55ce8c534d0783b5a3b81e8a66a', 'c556f618e19ba10e5448a909b30e3194']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "b563a84f7e0646b6239c507115d8d4a4"
}

