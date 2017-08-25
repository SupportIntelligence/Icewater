import "hash"

rule k3e9_51b93326d9a31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93326d9a31932"
     cluster="k3e9.51b93326d9a31932"
     cluster_size="100 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bb2340d7598ab088b138f4fb52f8ee5f', 'bf48846b70748918ca4df4d5458cd652', 'dfb4e3fabd8b22fbf4dfcc99ae34bc6a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

