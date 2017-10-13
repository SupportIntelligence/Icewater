import "hash"

rule n3e9_0db6538cda631932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0db6538cda631932"
     cluster="n3e9.0db6538cda631932"
     cluster_size="5856 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="graftor injector kolab"
     md5_hashes="['04b5da29fdfb30ed50ca70035861f4da', '1e88b957ad43e04f4e4cfbdb5bbe4b99', '152225d9f7b4555f67d53e7cd4551c8b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(573440,1024) == "e70a449578de0ebe3d727addf93b4766"
}

