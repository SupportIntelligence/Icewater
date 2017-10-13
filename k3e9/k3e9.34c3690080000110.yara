import "hash"

rule k3e9_34c3690080000110
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.34c3690080000110"
     cluster="k3e9.34c3690080000110"
     cluster_size="108 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="crytex hublo geksone"
     md5_hashes="['bbd101ec689504d5b4379c43a4c865c8', '13b263ab12fdc69655915c68515416e4', 'f539a70afd773a263bf74981e5cce68c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "8020f65f318b2e26a13e0ee9bfa117a5"
}

