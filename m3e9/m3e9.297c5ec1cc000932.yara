import "hash"

rule m3e9_297c5ec1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.297c5ec1cc000932"
     cluster="m3e9.297c5ec1cc000932"
     cluster_size="18650 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['066ebb6b5eb4411c83551f361717b7ee', '032fbe54eca445948ba500adedc920c5', '02743dc5f7af5436df5df2e432cdf438']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(5376,1088) == "28c561f0955cd72a51673e04ee096f3e"
}

