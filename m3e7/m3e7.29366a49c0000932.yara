import "hash"

rule m3e7_29366a49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.29366a49c0000932"
     cluster="m3e7.29366a49c0000932"
     cluster_size="31 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="picsys hidp prng"
     md5_hashes="['9fed10b9d2101254917a98d7928a768d', '1d2a36d554f297ffd1a315aa39993a15', 'a6c2c9683cf16b47e1696037fc48e16f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(12288,1024) == "5ca89cd02249aeb029067905d1ba389a"
}

