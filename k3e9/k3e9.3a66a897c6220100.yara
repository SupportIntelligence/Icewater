import "hash"

rule k3e9_3a66a897c6220100
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3a66a897c6220100"
     cluster="k3e9.3a66a897c6220100"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ac0f7e6292a710de1a235be6ea5a78f5', 'b75f7d5b0e31875f6b222398fd8f569c', 'c8a8c6e66dd7a1f6f951ab18d56b7bbf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "9a1dd280d47f8a52d50d6f78ec240b52"
}

