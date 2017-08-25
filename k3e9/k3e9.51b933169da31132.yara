import "hash"

rule k3e9_51b933169da31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b933169da31132"
     cluster="k3e9.51b933169da31132"
     cluster_size="132 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b2808093b67a055e72078f10270bcc86', '294fea29cd376e8006684366912244a1', '06aa0f013d51fa7454802d275304de65']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "5ab8258470efa3d600fcbe17d59a8cd4"
}

