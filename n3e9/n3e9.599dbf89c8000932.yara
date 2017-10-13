import "hash"

rule n3e9_599dbf89c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.599dbf89c8000932"
     cluster="n3e9.599dbf89c8000932"
     cluster_size="14445 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="elzob zusy shiz"
     md5_hashes="['0023e3f6ad4afa979fdf9d5441d00de2', '08db91450c2243863a50a3fd0a99203a', '07468e5d8696e0bc43b04daf6a380252']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(14104,1024) == "113b12abbc212dae31c2a6c7b4076c19"
}

