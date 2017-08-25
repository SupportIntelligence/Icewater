import "hash"

rule k3e9_17e31b121ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e31b121ee31132"
     cluster="k3e9.17e31b121ee31132"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a9a4eb1920a58d0c5303088c78fabce6', 'a07bc5acff3126135062ed031fba0ecc', 'aaa7d60c01400bcdb2e52ccae9c8a2df']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8704,256) == "4cecd67bfd344916fbf73bfee5da9c8f"
}

