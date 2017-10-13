import "hash"

rule m3e7_1c5a6a9dc6620b40
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.1c5a6a9dc6620b40"
     cluster="m3e7.1c5a6a9dc6620b40"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut prepender shodi"
     md5_hashes="['ba91b005c6894a59352babc3187882dc', '4e601e094c83cd03faef1ab4f726a6c2', 'b23538a545f7a41b887af3b3f6e8e7f4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(12288,1024) == "8e58efdccc5d126553629034a59cc997"
}

