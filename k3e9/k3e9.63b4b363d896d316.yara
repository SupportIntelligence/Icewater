import "hash"

rule k3e9_63b4b363d896d316
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d896d316"
     cluster="k3e9.63b4b363d896d316"
     cluster_size="372 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ae3e50cfe7d97993970384dbf73b4bed', 'c7d65e2e1731b257072e8ff2e03d484a', 'c3c511c511f0c0f305dc0ce9da647b2e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,256) == "fe88f5030104b15926c91a52764ce5e7"
}

