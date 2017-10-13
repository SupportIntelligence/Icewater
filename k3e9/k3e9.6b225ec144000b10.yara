import "hash"

rule k3e9_6b225ec144000b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b225ec144000b10"
     cluster="k3e9.6b225ec144000b10"
     cluster_size="30325 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="generickd upatre selfdel"
     md5_hashes="['010368425eb993bda988228cb538901e', '00b0cf073d57bf661df70d0ff55cae42', '036e9cecdb65b2bc030e1ad83b46013e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "9c142f385436c5fcfa043a13f366fc77"
}

