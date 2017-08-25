import "hash"

rule k3e9_17e30a961ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e30a961ee31132"
     cluster="k3e9.17e30a961ee31132"
     cluster_size="123 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['097a890fdd90df0f45fb57364e5b9939', 'db322f1323dcbfb7d7583bd6608a4be7', 'a58c19f4a4c0b67cb1c9c7ee2dbe4197']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "2fb80b5f3b6f045f2a5bf05d2c176dae"
}

