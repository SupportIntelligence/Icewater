import "hash"

rule n3e9_51972ec9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.51972ec9c8000932"
     cluster="n3e9.51972ec9c8000932"
     cluster_size="8489 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="banker shiz backdoor"
     md5_hashes="['0c2a005f83cb86b9113c85a7a58363de', '1694bd9f2b2b0fa0bb5f02f937482746', '0b68148a534577d8e9026280befd209f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(14120,1024) == "113b12abbc212dae31c2a6c7b4076c19"
}

