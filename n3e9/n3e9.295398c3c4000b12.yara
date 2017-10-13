import "hash"

rule n3e9_295398c3c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.295398c3c4000b12"
     cluster="n3e9.295398c3c4000b12"
     cluster_size="180 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="domaiq bundler lollipop"
     md5_hashes="['028709a3e52e741abab1570f495d2479', 'c69d711c006f2d5394a6bdc948afaf0a', '35a9300f996e98e685ef8ed49d743319']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(310272,1024) == "58706a4a7118520bee7bad6e74aae705"
}

