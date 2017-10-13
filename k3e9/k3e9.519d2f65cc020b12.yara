import "hash"

rule k3e9_519d2f65cc020b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.519d2f65cc020b12"
     cluster="k3e9.519d2f65cc020b12"
     cluster_size="26 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="crytex hublo geksone"
     md5_hashes="['e11902e1d873a2aae021165d60fb61f2', 'bfe9a5963e07ad2d4246df79bbe4a5d0', 'b303820d0b9a321808f748ad9ff540ec']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "9e01bc2eb8f720e192b813c6730b190a"
}

