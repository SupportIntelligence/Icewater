import "hash"

rule k3e9_51b933169da31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b933169da31932"
     cluster="k3e9.51b933169da31932"
     cluster_size="428 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c2bb9459da8ae81519a440df39363937', 'a34a017993fc37c7fdaae984eb31dd0e', 'b8cbd9aae55ffc892127ad1af318721b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(21504,256) == "b95d9c1d9fd9adf69978e28f8b6de1c0"
}

