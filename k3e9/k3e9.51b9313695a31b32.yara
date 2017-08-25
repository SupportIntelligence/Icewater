import "hash"

rule k3e9_51b9313695a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b9313695a31b32"
     cluster="k3e9.51b9313695a31b32"
     cluster_size="28 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['72b16d2fd638089cb740af1eef11eb45', 'dc57699c3b489fad0e85301a578be1cf', 'a2e527b560753d75181e9bd586f9d347']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "a620adcc65253f2a65dfc0f69b10f2c4"
}

