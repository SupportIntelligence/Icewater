import "hash"

rule n3e9_0109cb9483e31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109cb9483e31916"
     cluster="n3e9.0109cb9483e31916"
     cluster_size="58 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="syncopate unwanted malicious"
     md5_hashes="['85cbbee617f006ec53a593ac876b6fa0', 'c69cfd5f8eadce690106f67f23f2426a', '6536b0d9437098559eaa21ac1ac1f2fb']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(300544,1024) == "eab6c65529bf227e68e6c8e91e24453f"
}

