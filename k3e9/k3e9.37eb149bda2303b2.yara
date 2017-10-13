import "hash"

rule k3e9_37eb149bda2303b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.37eb149bda2303b2"
     cluster="k3e9.37eb149bda2303b2"
     cluster_size="76 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="upatre trojandownloader kryptik"
     md5_hashes="['dd8d8d17a5663302ba40e57f2ad57a88', '84aba9dc8bf98d240ffcae7e1fdc5eb4', '8b21294de93a0cfadc6322ee8f4f9515']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(35840,1024) == "e838d409639bc516b49e963a461002ea"
}

