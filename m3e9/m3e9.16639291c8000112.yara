import "hash"

rule m3e9_16639291c8000112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16639291c8000112"
     cluster="m3e9.16639291c8000112"
     cluster_size="12525 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="tinba crypt emotet"
     md5_hashes="['02d5b16156cc4dd96a5f823a8f47eb2a', '06e6e47406d5a85e8b24395488c75b6b', '08143920e6266477e0351ada656a1934']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(6142,1024) == "e525bc9c21ab6fbf303b9c9addf3e980"
}

