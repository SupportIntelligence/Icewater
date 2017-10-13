import "hash"

rule k3e9_3366bcc1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3366bcc1c8000932"
     cluster="k3e9.3366bcc1c8000932"
     cluster_size="2031 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="bublik generickd upatre"
     md5_hashes="['3d305188642f7f0073649e449f8fe5b0', '1b7dda101ffe72e2d2a8346ebb0f26fb', '2a70de1358f85501ca045336ed19f326']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6656,1152) == "e8a4259b91475b07dde96da84446983f"
}

