import "hash"

rule k3e9_6a928299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a928299c2200b12"
     cluster="k3e9.6a928299c2200b12"
     cluster_size="4903 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="androm downloadguide ocna"
     md5_hashes="['05b8d1bfaef56d0adc6a8bece3115305', '04f7b24092b04da9b8a34739b711f3c5', '0ec9c89f44e2acb26f8e4192c4370ab7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(7312,1047) == "69b2f07a5a7b2898a7b769ae47a0f906"
}

