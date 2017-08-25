import "hash"

rule m3e9_0da18a41229dcb36
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0da18a41229dcb36"
     cluster="m3e9.0da18a41229dcb36"
     cluster_size="14352 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="cripack yakes tpyn"
     md5_hashes="['058bf4c2434ac2df3529719e92f4c698', '058bf4c2434ac2df3529719e92f4c698', '021f1405123f61e5220b0fa83ccd46e5']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(200960,256) == "b8b8967894ee6ba957b4cad9e0d53cbb"
}

