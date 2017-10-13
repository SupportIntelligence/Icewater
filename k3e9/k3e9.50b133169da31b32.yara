import "hash"

rule k3e9_50b133169da31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.50b133169da31b32"
     cluster="k3e9.50b133169da31b32"
     cluster_size="48 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d0696981c5c5aed89ee83598f54203f4', 'cd03e8ee1552e299029bac9bd85693b6', 'bc7a878b03b13be341b7e8eda03faf11']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "a2c8c0039854981798c6825d650e8979"
}

