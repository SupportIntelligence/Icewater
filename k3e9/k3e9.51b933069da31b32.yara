import "hash"

rule k3e9_51b933069da31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b933069da31b32"
     cluster="k3e9.51b933069da31b32"
     cluster_size="121 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e9a3156d518bbf88902fd6f45fef10b1', 'd0f165d6422adcc0bd395ea5bcb63853', '54bd23c30acfac9fb081dec8b67e859d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "a620adcc65253f2a65dfc0f69b10f2c4"
}

