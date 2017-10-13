import "hash"

rule m3ed_531403b999246d16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.531403b999246d16"
     cluster="m3ed.531403b999246d16"
     cluster_size="77 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b825d397d66c3fd63ed165cacfad23fb', '40a2cf67513e62baef3d495d31838e5d', '26bea5d666b7e9012f681f8562c8a3d1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(135168,1024) == "52cb6988b2f04ce844376970cd99da9e"
}

