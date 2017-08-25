import "hash"

rule k3e9_63146fb11cc26b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fb11cc26b16"
     cluster="k3e9.63146fb11cc26b16"
     cluster_size="26 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d4dde03afb75e970da2571ab7c961e91', 'ed48240e724c2f7d3cd70cfe30ec2c18', 'bb6a5eba576e25d192cb28f96cde7094']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

