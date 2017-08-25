import "hash"

rule k3e9_63b4b363d8b6d316
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d8b6d316"
     cluster="k3e9.63b4b363d8b6d316"
     cluster_size="158 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ce7e4f0ad3a5869f5a08d54d2ed24651', 'ade8069545748f8160942dbc565252cb', '07b13a3906e46fecbf01d2a964cdc06a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,256) == "fe88f5030104b15926c91a52764ce5e7"
}

