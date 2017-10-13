import "hash"

rule k3e9_31656a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.31656a48c0000932"
     cluster="k3e9.31656a48c0000932"
     cluster_size="216 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="small generickd trojandownloader"
     md5_hashes="['53e7aa97ef8b2d4e056ecb93bec59302', 'b967ac4b4df4ff0e1e757884b16c74b9', '509a8194314a10d92aa9d43ccc6888e6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(13927,1127) == "ffce7d783333226b2a5b9678407f5545"
}

