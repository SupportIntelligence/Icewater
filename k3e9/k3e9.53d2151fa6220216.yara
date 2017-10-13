import "hash"

rule k3e9_53d2151fa6220216
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.53d2151fa6220216"
     cluster="k3e9.53d2151fa6220216"
     cluster_size="1373 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zbot supatre upatre"
     md5_hashes="['7bf678e601d3dceaa15f08f073113a2b', '3b0d3e399f23c572512b60f3067c091a', '0f2935149c4eb09d0d7eee88ea08e6bd']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "e334cf7360ec06be246d4f1741ec0326"
}

