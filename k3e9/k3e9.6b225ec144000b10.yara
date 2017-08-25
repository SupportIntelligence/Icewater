import "hash"

rule k3e9_6b225ec144000b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b225ec144000b10"
     cluster="k3e9.6b225ec144000b10"
     cluster_size="27086 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="generickd upatre selfdel"
     md5_hashes="['01b4dbccb69ca59b58c105c1d9ad90c8', '00581f0886e5372e6e5701632dc5e578', '01d11a9eb4220684e1caa0a3bd90d2de']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "9c142f385436c5fcfa043a13f366fc77"
}

