import "hash"

rule m3e7_29366b49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.29366b49c0000932"
     cluster="m3e7.29366b49c0000932"
     cluster_size="46 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="picsys hidp prng"
     md5_hashes="['0dfbb69cb6442629f9d84fa9f6acd088', '2c705db9368bbeba9d0db2c0262b87bc', 'ed80ce59477aaa8b0edcfca7c229bed2']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(12288,1024) == "5ca89cd02249aeb029067905d1ba389a"
}

