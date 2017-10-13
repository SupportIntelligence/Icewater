import "hash"

rule m3e9_4aa2ea4500001112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4aa2ea4500001112"
     cluster="m3e9.4aa2ea4500001112"
     cluster_size="14747 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="vilsel lamechi riskware"
     md5_hashes="['014cfcb6e3abdfa3969e25ffe6ece1e3', '008b7ae83bf692e176668fe7259b649c', '03eb61792aa20429ff2eec117c0a7c79']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(4096,1024) == "3bd5904065a027e156b4eaa6232d9b16"
}

