import "hash"

rule m3e9_43e6a44580001112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.43e6a44580001112"
     cluster="m3e9.43e6a44580001112"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="upatre kryptik trojandownloader"
     md5_hashes="['e48c8caa23d8855968a87979d9dfbce9', 'bc4f8d8b5aa7b45ec0cf37efd789090a', '2f74eddd158236f1f081ff8c65311669']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(66532,1052) == "4420c519b75f9b12079ab50a22acfc28"
}

