import "hash"

rule m3e9_619c91e9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.619c91e9c2200b16"
     cluster="m3e9.619c91e9c2200b16"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack virut"
     md5_hashes="['827885169b54b001bc00e025261f72ad', '5e350dc3594d6fb7a81e7ae8e6042663', 'a067695c003b8bd45e8c6a38661177c1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(99262,1035) == "838a52846d283a2e8bf58bfaebeef5c9"
}

