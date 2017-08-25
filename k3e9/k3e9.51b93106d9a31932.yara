import "hash"

rule k3e9_51b93106d9a31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93106d9a31932"
     cluster="k3e9.51b93106d9a31932"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c9e64194c68dcad44053387806e31b12', '4610d9ca9f60dc718ebbaa7f97a53bba', 'af22edcf79e15d1ff2c5e7254f4f1fab']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

