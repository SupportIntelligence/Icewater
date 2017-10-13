import "hash"

rule m3ed_6b322b25d5bb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.6b322b25d5bb1912"
     cluster="m3ed.6b322b25d5bb1912"
     cluster_size="308 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['f4573558487301c5275e89a3b7af51d0', 'e76d96aa81ee9b776a530745704f3328', 'c6da9f1462de3dd50396aeb6bd4f159b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(83968,1024) == "8d2fafbf55fcfd78b7856bd91338e652"
}

