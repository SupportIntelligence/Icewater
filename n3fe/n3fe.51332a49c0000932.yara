import "hash"

rule n3fe_51332a49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fe.51332a49c0000932"
     cluster="n3fe.51332a49c0000932"
     cluster_size="864 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     md5_hashes="['0139e6d893be688f13c42710e02bfdbd', '00578fef74f95b583a41035182adcc99', '31ecd8631e2be18fd537d4d70d73d38c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(266880,1152) == "2e17978f0ca6fb1c38c1adee35ab8d8e"
}

