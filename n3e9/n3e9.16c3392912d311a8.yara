import "hash"

rule n3e9_16c3392912d311a8
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.16c3392912d311a8"
     cluster="n3e9.16c3392912d311a8"
     cluster_size="102 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious attribute engine"
     md5_hashes="['81c02f03a22daa87fc246c9a2ec29dc7', '1faba608f7387ee8b57f6b45aa2d1e4d', '322313ecb58bcb84dd5863ab50cc1b0e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(83484,1026) == "63e6c91fc4db094e77636a3385502153"
}

