import "hash"

rule m3e7_293e5cc1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.293e5cc1cc000932"
     cluster="m3e7.293e5cc1cc000932"
     cluster_size="76 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="picsys hidp prng"
     md5_hashes="['c7ac2e802524329d3b0057e07c061b17', '93013c2c7a40c589b1f3deb58c82a659', '5e1bd068bf24e5fdef4f1807096b2a11']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(12288,1024) == "5ca89cd02249aeb029067905d1ba389a"
}

