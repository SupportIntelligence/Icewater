import "hash"

rule m3ed_6b122b2595bb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.6b122b2595bb1912"
     cluster="m3ed.6b122b2595bb1912"
     cluster_size="190 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['baf6b75f8170dd74614b7ba6db344344', 'ac91cb41592b65526ea95896b5cc27ea', '8a20136e8c3ca12c1e414e68e2c253d3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(83968,1024) == "8d2fafbf55fcfd78b7856bd91338e652"
}

