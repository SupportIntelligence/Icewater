import "hash"

rule k3e9_51b13136dda31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13136dda31b32"
     cluster="k3e9.51b13136dda31b32"
     cluster_size="230 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b2a92d1cad8a2b5b0e827ba78d65e95b', 'b0d7ea1a757ed1cf23c878dc5358f511', 'fdd8da2c90bc391570313d2bfb7e4e4e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(23552,256) == "432963b0020815cd33e0e135d9e30a3f"
}

