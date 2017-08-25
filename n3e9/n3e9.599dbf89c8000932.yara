import "hash"

rule n3e9_599dbf89c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.599dbf89c8000932"
     cluster="n3e9.599dbf89c8000932"
     cluster_size="12402 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="elzob zusy shiz"
     md5_hashes="['01add185263175353e183a8bb1c5cdec', '0c3613c7c277c56ac45fb1ec36088edd', '007003ea68eb256657a23c6be5a26f57']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(14104,1024) == "113b12abbc212dae31c2a6c7b4076c19"
}

