import "hash"

rule k3e9_51b93136dda30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93136dda30932"
     cluster="k3e9.51b93136dda30932"
     cluster_size="12 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a6d043963ab4962025b75c5941e609d7', 'e5b398ddb8da4acf9dbb2c9a7eebae24', 'b6211542f7c5d69ad439f3af97e6a43c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "a2c8c0039854981798c6825d650e8979"
}

